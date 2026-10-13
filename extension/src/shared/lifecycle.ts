// The background script's lifecycle decisions, kept free of browser APIs so that they can be unit
// tested: the idle lock's decision, the one unlocked session with a single open in flight, and the
// one-at-a-time sync with a rerun flag.

/**
 * Whether the vault locks now (docs/firefox.md, Background script): when no user action is
 * recorded, or when `idleMinutes` have passed since the last one, the boundary included.
 */
export function idleExpired(now: number, lastActivity: number | null, idleMinutes: number): boolean {
  return lastActivity === null || now - lastActivity >= idleMinutes * 60_000;
}

export interface Lockable {
  lock(): void;
  free(): void;
}

/**
 * Holds the one unlocked session. Concurrent callers share one open in flight; a drop while an
 * open is in flight discards its result (locking and freeing it), so a lock can never be undone by
 * an open that started before it.
 */
export class SessionSlot<T extends Lockable> {
  private current: T | null = null;
  private opening: Promise<T | null> | null = null;
  private generation = 0;

  /** The session, opening it with `open` when there is none. */
  get(open: () => Promise<T | null>): Promise<T | null> {
    if (this.current !== null) return Promise.resolve(this.current);
    if (this.opening !== null) return this.opening;
    const generation = this.generation;
    const opening = open().then(
      (s) => {
        if (generation !== this.generation) {
          s?.lock();
          s?.free();
          return null;
        }
        this.current = s;
        return s;
      },
      (e) => {
        throw e;
      },
    ).finally(() => {
      if (this.opening === opening) this.opening = null;
    });
    this.opening = opening;
    return opening;
  }

  /** The session, if one is open, without opening one. */
  peek(): T | null {
    return this.current;
  }

  /** Locks and frees the session, and discards any open in flight. */
  drop(): void {
    this.generation++;
    this.opening = null;
    this.current?.lock();
    this.current?.free();
    this.current = null;
  }
}

/**
 * Runs `task` one at a time. A request while it runs sets a flag that runs it once more
 * afterwards; every request made meanwhile resolves when that last run finishes.
 */
export function coalesce(task: () => Promise<void>): () => Promise<void> {
  let running: Promise<void> | null = null;
  let again = false;
  return () => {
    if (running !== null) {
      again = true;
      return running;
    }
    running = (async () => {
      try {
        do {
          again = false;
          await task();
        } while (again);
      } finally {
        running = null;
      }
    })();
    return running;
  };
}
