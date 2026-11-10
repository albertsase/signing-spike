/**
 * Abstraction the real apps will use (libs/signing). The apps only know this interface, so the provider
 * (AutoFirma today, remote QTSP or server seal tomorrow) can change without touching them.
 */
export interface SigningService {
  readonly name: string;
  /** Signs the given PDF and returns the SAME PDF with the new signature appended (PAdES, incremental). */
  signPdf(pdf: ArrayBuffer, options?: SignOptions): Promise<ArrayBuffer>;
}

/** Rectangle on a page in PDF points, origin at the lower-left corner; page is 1-based. Defined by the PDF template. */
export interface SignatureBox {
  page: number;
  llx: number;
  lly: number;
  urx: number;
  ury: number;
}

export interface SignOptions {
  reason?: string;
  /** Role shown in the visible signature (e.g. DO, IO). */
  role?: string;
  /** If present the signature is VISIBLE inside this rectangle; otherwise it is invisible. */
  box?: SignatureBox;
}

export class SigningError extends Error {
  constructor(message: string, public readonly kind: string = 'UNKNOWN') {
    super(message);
  }
}

declare const AutoScript: any; // from vendor/autoscript.js (official Cliente @firma, GPL/EUPL)

/** AutoFirma through the official JS client (WebSocket to the local app; the private key never leaves the machine). */
export class AutoFirmaSigner implements SigningService {
  readonly name = 'AutoFirma';
  private loaded = false;

  async signPdf(pdf: ArrayBuffer, options: SignOptions = {}): Promise<ArrayBuffer> {
    if (typeof AutoScript === 'undefined') {
      throw new SigningError('The AutoFirma client script (autoscript.js) is not loaded.', 'CLIENT_NOT_LOADED');
    }
    if (!this.loaded) {
      AutoScript.cargarAppAfirma(); // detects WebSocket / protocol; shows its own "install AutoFirma" dialog if needed
      this.loaded = true;
    }
    const dataB64 = toBase64(pdf);
    const params = this.buildParams(options).join('\n');

    return new Promise<ArrayBuffer>((resolve, reject) => {
      AutoScript.sign(
        dataB64,
        'SHA256withRSA',
        'PAdES',
        params,
        (signedB64: string) => resolve(fromBase64(signedB64)),
        (errorType: string, errorMessage: string) =>
          reject(new SigningError(errorMessage || errorType || 'AutoFirma error', errorType))
      );
    });
  }

  /** Parameter names verified against PdfExtraParams.java of the Cliente @firma project (master). */
  private buildParams(options: SignOptions): string[] {
    // No signatureSubFilter: AutoFirma's default ETSI.CAdES.detached is the PAdES baseline one (what eIDAS expects).
    const p: string[] = [
      // REQUIRED: by default AutoFirma rewrites the whole PDF on the first signature (append mode only when the PDF
      // already has signatures), which breaks our "new version starts with the previous bytes" rule.
      'alwaysCreateRevision=true',
    ];
    if (options.reason) {
      p.push('signReason=' + options.reason);
    }
    // No timestamp parameters on purpose: AutoFirma 1.9.0 silently drops the signature timestamp (bug in
    // PdfTimestamper.buildCmsTimeStamper, getConstructor(tsaParamsClass.getClass())). The SERVER timestamps instead.
    if (options.box) {
      const b = options.box;
      p.push(
        'signaturePage=' + b.page,
        'signaturePositionOnPageLowerLeftX=' + Math.round(b.llx),
        'signaturePositionOnPageLowerLeftY=' + Math.round(b.lly),
        'signaturePositionOnPageUpperRightX=' + Math.round(b.urx),
        'signaturePositionOnPageUpperRightY=' + Math.round(b.ury),
        // Single line on purpose: a "\n" inside a value breaks AutoFirma's parameter parser. The text wraps inside the box.
        'layer2Text=' +
          (options.role ? 'Firma (' + options.role + '): ' : '') +
          'Firmado por $$SUBJECTCN$$ el $$SIGNDATE=dd/MM/yyyy HH:mm:ss z$$',
        'layer2FontFamily=1', // Helvetica
        'layer2FontSize=8'
      );
    }
    return p;
  }
}

export function toBase64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + 0x8000)));
  }
  return btoa(s);
}

export function fromBase64(b64: string): ArrayBuffer {
  // AutoFirma may return URL-safe base64
  const s = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out.buffer;
}
