import { Icon } from "./Icon";

/**
 * The command composer - a compose-then-commit line above the KeyBar.
 *
 * Typing straight into a PTY is unforgiving on a phone: every keystroke is
 * already on the wire, so fixing a typo means backspacing over the network,
 * there is no cursor to move without the arrow keys, and the IME's autocorrect
 * happily rewrites flags and paths before you can see what it did. The composer
 * keeps the line local until you commit it - edit it like text, then send once.
 *
 * It is an `<input>`, not a `<textarea>`, and that is load-bearing: the browser
 * flattens a multi-line paste into a single line, so one Send is always exactly
 * one command. A textarea would let a pasted three-line script fire three
 * commands from one tap, with no chance to read them first.
 *
 * Committing appends `\r` - a PTY's Enter is a carriage return, not `\n`.
 *
 * Deliberately NOT here: a composer-local history. The KeyBar's up arrow already
 * sends `\x1b[A`, which is the *shell's* history - the real one, with the
 * commands you ran from the laptop in it. A second list would drift from that
 * and leave two different "last command"s a tap apart.
 */
export function CommandBar(props: {
  value: string;
  onInput: (s: string) => void;
  /** Receives the composed line WITHOUT a trailing newline; the caller commits. */
  onSubmit: () => void;
  /** Fires when the field takes focus, so the app can route Paste here and drop
   *  the Ctrl latch (which only ever applies to the terminal). */
  onFocus: () => void;
  /** Fires on blur - the app needs it to know whether the keyboard is still up,
   *  since this field is one of two surfaces that can be holding it. */
  onBlur: () => void;
  /** Hands the element up so Paste can insert at the caret instead of the PTY. */
  ref: (el: HTMLInputElement) => void;
}) {
  const empty = () => !props.value.trim();

  return (
    <div class="portty-cmdbar" role="group" aria-label="Command composer">
      <input
        ref={props.ref}
        class="portty-cmdbar-input"
        type="text"
        value={props.value}
        onFocus={props.onFocus}
        onBlur={props.onBlur}
        placeholder="Type a command…"
        // Every one of these off: a shell command is not prose. Autocorrect
        // rewriting `-rf` or capitalizing a path is the exact failure the
        // composer exists to prevent.
        autocapitalize="off"
        autocorrect="off"
        autocomplete="off"
        spellcheck={false}
        enterkeyhint="send"
        aria-label="Command to send to the terminal"
        onInput={(event) => props.onInput(event.currentTarget.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            event.preventDefault(); // keep the newline out of the field
            props.onSubmit();
          }
        }}
      />
      <button
        class="portty-cmdbar-send"
        disabled={empty()}
        onClick={props.onSubmit}
        title="Send this command"
        aria-label="Send this command to the terminal"
      >
        <Icon name="send" />
      </button>
    </div>
  );
}
