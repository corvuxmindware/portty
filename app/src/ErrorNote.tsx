import { createEffect, createSignal, For, on, onMount, Show } from "solid-js";
import { Icon } from "./Icon";
import "./ErrorNote.css";

/**
 * Text with `backticked` commands shown as code, so "run `portty pair`" reads
 * as something to type rather than as prose. Plain text otherwise - error text
 * is never treated as markup.
 */
export function RichText(props: { text: string }) {
  return (
    <For each={props.text.split("`")}>
      {(part, index) => (index() % 2 === 1 ? <code>{part}</code> : part)}
    </For>
  );
}

/**
 * One message for the person, with the technical text one tap away.
 *
 * The message says what happened and what to do next (lib/friendlyError.ts).
 * `detail` is the raw error for support - hidden until "Details" is tapped,
 * selectable, and copyable, because a support request can't include a
 * screenshot (Portty blocks them) and nobody should have to retype a stack of
 * error text by hand.
 */
export function ErrorNote(props: {
  message: string;
  detail?: string;
  /** "error" (the default) draws the eye; "info" is a quiet state line. */
  tone?: "error" | "info";
  /** One next step that the app can take for the person. */
  action?: { label: string; run: () => void };
  onDismiss?: () => void;
  /** Copies the detail; the button is shown only when this is given. */
  copy?: (text: string) => Promise<boolean>;
  /** Scroll the note into view when it appears - for a long, scrolling screen
   *  where it would otherwise land below the fold. */
  reveal?: boolean;
  class?: string;
}) {
  let note: HTMLDivElement | undefined;
  const [open, setOpen] = createSignal(false);
  const [copied, setCopied] = createSignal(false);
  onMount(() => {
    if (!props.reveal || !note) return;
    const still =
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    note.scrollIntoView({ block: "nearest", behavior: still ? "auto" : "smooth" });
  });
  // A new error starts folded: details opened for the last one say nothing
  // about this one.
  createEffect(
    on(
      () => props.detail,
      () => {
        setOpen(false);
        setCopied(false);
      },
      { defer: true },
    ),
  );
  const isError = () => (props.tone ?? "error") === "error";
  return (
    <div
      ref={note}
      class={`portty-note${props.class ? ` ${props.class}` : ""}`}
      classList={{ "portty-note--error": isError() }}
      role={isError() ? "alert" : "status"}
    >
      <Show when={isError()}>
        <Icon name="warning" class="portty-note__icon" />
      </Show>
      <div class="portty-note__body">
        <p class="portty-note__message">
          <RichText text={props.message} />
        </p>
        <Show when={props.action || props.detail}>
          <div class="portty-note__actions">
            <Show when={props.action}>
              {(action) => (
                <button type="button" class="portty-note__action" onClick={() => action().run()}>
                  {action().label}
                </button>
              )}
            </Show>
            <Show when={props.detail}>
              <button
                type="button"
                class="portty-note__link"
                aria-expanded={open()}
                onClick={() => setOpen((value) => !value)}
              >
                {open() ? "Hide details" : "Details"}
              </button>
            </Show>
          </div>
        </Show>
        <Show when={open() && props.detail}>
          {(detail) => (
            <div class="portty-note__detail">
              <pre>{detail()}</pre>
              <Show when={props.copy}>
                {(copy) => (
                  <button
                    type="button"
                    class="portty-note__link"
                    onClick={() => void copy()(detail()).then(setCopied)}
                  >
                    {copied() ? "Copied" : "Copy details"}
                  </button>
                )}
              </Show>
            </div>
          )}
        </Show>
      </div>
      <Show when={props.onDismiss}>
        {(dismiss) => (
          <button
            type="button"
            class="portty-note__dismiss"
            aria-label="Dismiss this message"
            onClick={() => dismiss()()}
          >
            <Icon name="close" />
          </button>
        )}
      </Show>
    </div>
  );
}
