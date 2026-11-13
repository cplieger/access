// Its own module because location is non-configurable: a test replaces this import instead.
/** @internal */
export function assign(url: string): void {
  globalThis.location.assign(url);
}
