import { createSignal, onCleanup, onMount, Show } from "solid-js";
import jsQR from "jsqr";
import { Icon } from "./Icon";

/**
 * Camera-based QR scanner for the pairing flow. Lifted from Corvux's
 * `QrScanner.tsx` (same stack, same Samsung ultra-wide lens problem solved).
 *
 * Opens the back-facing camera via `getUserMedia`, scans each frame with jsQR,
 * and calls `onResult` once with the decoded string (the host's NodeId), then
 * tears the camera down.
 *
 * ## Lens selection (the Samsung ultra-wide problem)
 * `facingMode: "environment"` alone picks an arbitrary back camera - on
 * multi-lens phones (e.g. Samsung) that's frequently the **ultra-wide**, which
 * can't focus on a close QR and shrinks it in a wide field of view. We pick the
 * main back lens by label / lowest camera2 index, enable continuous autofocus,
 * and expose a **Switch camera** button as the reliable manual fallback.
 *
 * ## Android WebView
 * `getUserMedia({video})` triggers wry's `onPermissionRequest` → the OS CAMERA
 * grant (declared in AndroidManifest.xml). `playsinline` keeps the preview from
 * going fullscreen.
 *
 * The PIN is intentionally NOT in the QR - it stays manual as the out-of-band
 * MitM check. Scanning only fills the ticket (here, the bare NodeId).
 */

type FocusCapabilities = MediaTrackCapabilities & { focusMode?: string[]; torch?: boolean };
type FocusConstraint = MediaTrackConstraintSet & { focusMode?: string; torch?: boolean };

export function QrScanner(props: {
  onResult: (ticket: string) => void;
  onError: (message: string) => void;
  onCancel: () => void;
}) {
  let video!: HTMLVideoElement;
  let canvas!: HTMLCanvasElement;
  const [status, setStatus] = createSignal<"starting" | "scanning">("starting");
  const [cameras, setCameras] = createSignal<MediaDeviceInfo[]>([]);
  const [camIndex, setCamIndex] = createSignal(0);
  const [torchSupported, setTorchSupported] = createSignal(false);
  const [torchOn, setTorchOn] = createSignal(false);

  let stream: MediaStream | null = null;
  let raf: number | null = null;
  let done = false;

  function stopStream() {
    if (stream) {
      for (const track of stream.getTracks()) track.stop();
      stream = null;
    }
  }
  function cleanup() {
    done = true;
    if (raf !== null) {
      cancelAnimationFrame(raf);
      raf = null;
    }
    stopStream();
  }
  onCleanup(cleanup);

  async function openCamera(deviceId?: string): Promise<void> {
    stopStream();
    // High resolution: a dense QR needs enough pixels for jsQR to resolve modules.
    const resolution = { width: { ideal: 1280 }, height: { ideal: 720 } };
    const videoConstraints: MediaTrackConstraints = deviceId
      ? { deviceId: { exact: deviceId }, ...resolution }
      : { facingMode: { ideal: "environment" }, ...resolution };
    stream = await navigator.mediaDevices.getUserMedia({
      video: videoConstraints,
      audio: false,
    });
    video.muted = true;
    video.setAttribute("playsinline", "true");
    video.srcObject = stream;
    try {
      await video.play();
    } catch {
      /* some webviews resolve play() late; the rAF loop still reads frames */
    }
    const track = stream.getVideoTracks()[0];
    // A fresh track owns its own torch state - reset before re-probing.
    setTorchSupported(false);
    setTorchOn(false);
    try {
      if (track && typeof track.getCapabilities === "function") {
        const caps = track.getCapabilities() as FocusCapabilities;
        if (caps.focusMode?.includes("continuous")) {
          await track.applyConstraints({
            advanced: [{ focusMode: "continuous" } as FocusConstraint],
          });
        }
        // Torch is absent on many front cameras and all iOS WKWebView tracks;
        // only surface the control when the device actually reports it.
        setTorchSupported(caps.torch === true);
      }
    } catch {
      /* focus/torch probing is best-effort; scanning works without it */
    }
  }

  async function toggleTorch() {
    const track = stream?.getVideoTracks()[0];
    if (!track) return;
    const next = !torchOn();
    try {
      await track.applyConstraints({ advanced: [{ torch: next } as FocusConstraint] });
      setTorchOn(next);
    } catch (e) {
      console.warn("qr-scanner: torch toggle failed", e);
      setTorchSupported(false); // device refused it - hide the control
    }
  }

  function backCameras(list: MediaDeviceInfo[]): MediaDeviceInfo[] {
    const vids = list.filter((d) => d.kind === "videoinput");
    const back = vids.filter((d) => /back|rear|environment/i.test(d.label));
    return back.length > 0 ? back : vids;
  }

  function preferredIndex(back: MediaDeviceInfo[]): number {
    const isAux = (l: string) =>
      /ultra|wide.?angle|tele|zoom|depth|mono|infrared|\bir\b/i.test(l);
    if (back.some((d) => isAux(d.label))) {
      const main = back.findIndex((d) => d.label && !isAux(d.label));
      if (main >= 0) return main;
    }
    // Samsung WebView: labels are "camera2 N, facing back" - main lens is the
    // lowest N.
    let bestIdx = 0;
    let bestN = Number.POSITIVE_INFINITY;
    back.forEach((d, i) => {
      const m = d.label.match(/camera2?\s+(\d+)/i);
      const n = m ? Number.parseInt(m[1], 10) : i;
      if (n < bestN) {
        bestN = n;
        bestIdx = i;
      }
    });
    return bestIdx;
  }

  function startLoop() {
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    const tick = () => {
      if (done) return;
      if (ctx && video.readyState >= video.HAVE_CURRENT_DATA) {
        const w = video.videoWidth;
        const h = video.videoHeight;
        if (w > 0 && h > 0) {
          canvas.width = w;
          canvas.height = h;
          ctx.drawImage(video, 0, 0, w, h);
          const frame = ctx.getImageData(0, 0, w, h);
          // attemptBoth: the host's terminal QR is dark-on-light, but terminal
          // rendering can be inconsistent - try both polarities to be safe.
          const code = jsQR(frame.data, w, h, { inversionAttempts: "attemptBoth" });
          if (code && code.data) {
            cleanup();
            props.onResult(code.data.trim());
            return;
          }
        }
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
  }

  onMount(async () => {
    if (!navigator.mediaDevices?.getUserMedia) {
      props.onError("Camera isn't available on this device - paste the code instead.");
      return;
    }
    try {
      await openCamera();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.warn("qr-scanner: getUserMedia rejected", e);
      props.onError(`Camera access failed: ${msg}`);
      return;
    }
    try {
      const back = backCameras(await navigator.mediaDevices.enumerateDevices());
      setCameras(back);
      if (back.length > 1) {
        const idx = preferredIndex(back);
        setCamIndex(idx);
        const want = back[idx]?.deviceId;
        const current = stream?.getVideoTracks()[0]?.getSettings().deviceId;
        if (want && want !== current) await openCamera(want);
      }
    } catch (e) {
      console.warn("qr-scanner: camera enumerate/select failed", e);
    }
    if (done) return;
    setStatus("scanning");
    startLoop();
  });

  async function switchCamera() {
    const list = cameras();
    if (list.length < 2) return;
    const next = (camIndex() + 1) % list.length;
    setCamIndex(next);
    try {
      await openCamera(list[next]?.deviceId);
    } catch (e) {
      console.warn("qr-scanner: switch camera failed", e);
    }
  }

  return (
    <div class="space-y-2">
      <div
        class="relative mx-auto overflow-hidden rounded-2xl bg-black"
        style={{
          "aspect-ratio": "1 / 1",
          "max-width": "240px",
          border: "1px solid var(--border-strong)",
          "box-shadow": "0 0 30px rgba(163, 230, 53, 0.14)",
        }}
      >
        <video ref={video} class="h-full w-full object-cover" />
        <canvas ref={canvas} class="hidden" />
        {/* Aiming frame */}
        <div class="pointer-events-none absolute inset-5 rounded-xl border-2 border-lime-400/70" />
        <Show when={cameras().length > 1}>
          <button
            class="absolute bottom-2 right-2 rounded-lg bg-black/60 px-2.5 py-1 text-[11px] text-white backdrop-blur hover:bg-black/80"
            onClick={switchCamera}
          >
            Switch camera
          </button>
        </Show>
        <Show when={torchSupported()}>
          <button
            class="absolute bottom-2 left-2 inline-flex items-center gap-1 rounded-lg bg-black/60 px-2.5 py-1 text-[11px] text-white backdrop-blur hover:bg-black/80"
            onClick={toggleTorch}
            aria-pressed={torchOn()}
            aria-label={torchOn() ? "Turn flashlight off" : "Turn flashlight on"}
          >
            <Icon name="flashlight" />
            {torchOn() ? "On" : "Off"}
          </button>
        </Show>
      </div>
      <div class="portty-hint text-center">
        {status() === "starting" ? "Starting camera…" : "Point at the QR on the host's terminal"}
      </div>
      <button
        class="portty-link w-full text-center"
        onClick={() => {
          cleanup();
          props.onCancel();
        }}
      >
        Cancel scan
      </button>
    </div>
  );
}
