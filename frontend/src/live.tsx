import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { getToken } from "./api";
import type { Alert, LiveMessage } from "./types";

type Listener = (msg: LiveMessage) => void;

export interface Toast {
  id: number;
  alert: Alert;
}

interface LiveState {
  connected: boolean;
  eventsPerSecond: number;
  toasts: Toast[];
  dismissToast: (id: number) => void;
  subscribe: (fn: Listener) => () => void;
}

const LiveContext = createContext<LiveState | null>(null);

export function LiveProvider({ children }: { children: ReactNode }) {
  const [connected, setConnected] = useState(false);
  const [eventsPerSecond, setRate] = useState(0);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const listeners = useRef(new Set<Listener>());
  const counter = useRef(0);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry = 0;
    let closed = false;
    let timer: number | undefined;
    let ping: number | undefined;

    const connect = () => {
      const token = getToken();
      if (!token || closed) return;
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/api/ws`);
      ws.onopen = () => {
        ws?.send(token); // authenticate as the first frame (keeps the JWT out of URLs/logs)
        retry = 0;
        ping = window.setInterval(() => ws?.readyState === WebSocket.OPEN && ws.send("ping"), 25000);
      };
      ws.onmessage = (e) => {
        const msg = JSON.parse(e.data) as LiveMessage;
        if (msg.type === "hello") {
          setConnected(true);
          return;
        }
        if (msg.type === "ingest") counter.current += (msg.data as { count: number }).count;
        if (msg.type === "alert") {
          const alert = msg.data as Alert;
          if (alert.severity === "high" || alert.severity === "critical") {
            setToasts((t) => [...t.slice(-3), { id: alert.id, alert }]);
            window.setTimeout(() => setToasts((t) => t.filter((x) => x.id !== alert.id)), 8000);
          }
        }
        listeners.current.forEach((fn) => fn(msg));
      };
      ws.onclose = (e) => {
        setConnected(false);
        window.clearInterval(ping);
        if (closed || e.code === 4401) return;
        retry = Math.min(retry + 1, 6);
        timer = window.setTimeout(connect, 500 * 2 ** retry);
      };
    };
    connect();

    const rate = window.setInterval(() => {
      setRate(counter.current / 2);
      counter.current = 0;
    }, 2000);

    return () => {
      closed = true;
      window.clearTimeout(timer);
      window.clearInterval(rate);
      window.clearInterval(ping);
      ws?.close();
    };
  }, []);

  const subscribe = useCallback((fn: Listener) => {
    listeners.current.add(fn);
    return () => {
      listeners.current.delete(fn);
    };
  }, []);

  const dismissToast = useCallback(
    (id: number) => setToasts((t) => t.filter((x) => x.id !== id)),
    [],
  );

  return (
    <LiveContext.Provider value={{ connected, eventsPerSecond, toasts, dismissToast, subscribe }}>
      {children}
    </LiveContext.Provider>
  );
}

export function useLive(): LiveState {
  const ctx = useContext(LiveContext);
  if (!ctx) throw new Error("useLive outside LiveProvider");
  return ctx;
}

/** Run `fn` (debounced) whenever a live message of one of `types` arrives. */
export function useLiveRefresh(types: LiveMessage["type"][], fn: () => void, delay = 800) {
  const { subscribe } = useLive();
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const key = types.join(",");
  useEffect(() => {
    let timer: number | undefined;
    const wanted = new Set(key.split(","));
    const unsubscribe = subscribe((msg) => {
      if (!wanted.has(msg.type)) return;
      window.clearTimeout(timer);
      timer = window.setTimeout(() => fnRef.current(), delay);
    });
    return () => {
      window.clearTimeout(timer);
      unsubscribe();
    };
  }, [subscribe, key, delay]);
}
