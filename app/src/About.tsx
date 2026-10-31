import { For, Show, createSignal, onMount } from "solid-js";
import { getVersion } from "@tauri-apps/api/app";
import * as portty from "./lib/portty";
import { NOTICES_URL, splitNotices } from "./lib/notices";
import { Icon } from "./Icon";
import "./about.css";

/** The public source repository (Apache-2.0). */
const SOURCE_CODE_URL = "https://github.com/corvuxmindware/portty";

/**
 * About Portty: which app and protocol version this is, the open-source
 * licences, and where the source code lives. Reached from the (i) button on the
 * home screen.
 */
export function AboutScreen(props: { onBack: () => void; onLicences: () => void }) {
  const [version, setVersion] = createSignal<string | null>(null);
  const [protocol, setProtocol] = createSignal<string | null>(null);
  const [linkError, setLinkError] = createSignal(false);

  onMount(() => {
    getVersion()
      .then(setVersion)
      .catch(() => setVersion("unknown"));
    portty
      .appInfo()
      .then((info) => setProtocol(String(info.protocol_version)))
      .catch(() => setProtocol("unknown"));
  });

  const openSource = () => {
    setLinkError(false);
    portty.openExternal(SOURCE_CODE_URL).catch(() => setLinkError(true));
  };

  return (
    <div class="flex h-full flex-col">
      <header class="portty-header">
        <button class="portty-icon-btn" onClick={() => props.onBack()} title="Back" aria-label="Back">
          <Icon name="arrow-left" />
        </button>
        <span class="portty-header-title">About Portty</span>
      </header>

      <div class="mx-auto flex w-full max-w-md min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-5">
        <div class="portty-card">
          <dl class="portty-about-facts">
            <div class="portty-about-fact">
              <dt>App version</dt>
              <dd class="portty-about-version">{version() ?? "…"}</dd>
            </div>
            <div class="portty-about-fact">
              <dt>Protocol version</dt>
              <dd class="portty-about-protocol">{protocol() ?? "…"}</dd>
            </div>
          </dl>
          <p class="portty-hint portty-about-note">
            The app and the Portty program on your computer must use the same protocol version.
            If they stop connecting after an update, update both to the newest version.
          </p>
        </div>

        <div class="portty-card portty-about-links">
          <button type="button" class="portty-about-row" onClick={() => props.onLicences()}>
            <span>Open-source licences</span>
            <Icon name="arrow-right" />
          </button>
          <button type="button" class="portty-about-row" onClick={openSource}>
            <span>Source code</span>
            <Icon name="external-link" />
          </button>
        </div>
        <Show when={linkError()}>
          <p class="portty-hint" role="alert">
            Couldn't open the browser. The source code is at github.com/corvuxmindware/portty.
          </p>
        </Show>
        <p class="portty-hint">
          Portty is open-source software under the Apache License 2.0. It is built on many other
          open-source projects - thank you to all of them.
        </p>
      </div>
    </div>
  );
}

// Split once per app run: the file is static and ~400 KB.
let noticesCache: Promise<string[]> | null = null;

function loadNotices(): Promise<string[]> {
  noticesCache ??= fetch(NOTICES_URL)
    .then((response) => {
      if (!response.ok) throw new Error(`notices: HTTP ${response.status}`);
      return response.text();
    })
    .then(splitNotices)
    .catch((error: unknown) => {
      noticesCache = null; // let the next visit try again
      throw error;
    });
  return noticesCache;
}

/**
 * The full open-source notices, loaded from the app bundle only when this
 * screen opens. Each block is its own element so the WebView can skip laying
 * out the parts that are off screen.
 */
export function LicencesScreen(props: { onBack: () => void }) {
  const [blocks, setBlocks] = createSignal<string[] | null>(null);
  const [failed, setFailed] = createSignal(false);

  onMount(() => {
    loadNotices()
      .then(setBlocks)
      .catch(() => setFailed(true));
  });

  return (
    <div class="flex h-full flex-col">
      <header class="portty-header">
        <button class="portty-icon-btn" onClick={() => props.onBack()} title="Back" aria-label="Back">
          <Icon name="arrow-left" />
        </button>
        <span class="portty-header-title">Open-source licences</span>
      </header>

      <div class="portty-licences min-h-0 flex-1 overflow-y-auto" tabindex="0" aria-label="Open-source licences">
        <Show
          when={blocks()}
          fallback={
            <p class="portty-hint" role={failed() ? "alert" : "status"}>
              {failed() ? "Couldn't load the licences. Go back and open this page again." : "Loading…"}
            </p>
          }
        >
          {(list) => <For each={list()}>{(block) => <pre class="portty-licences-block">{block}</pre>}</For>}
        </Show>
      </div>
    </div>
  );
}
