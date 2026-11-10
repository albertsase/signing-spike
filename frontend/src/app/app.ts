import { Component, signal, computed } from '@angular/core';
import { AutoFirmaSigner, SignatureBox, SigningService } from './signing/signing.service';

const API = 'http://localhost:8080/api';

interface Signer { role: string; status: string; subject?: string; signedAt?: string; box?: SignatureBox; }
interface Doc { id: string; title: string; status: string; version: number; signers: Signer[]; }
interface SigInfo { subject: string; issuer: string; revocation: string; signDate: string; integrityOk: boolean; chainOk: boolean; revocationOk: boolean; timestampOk: boolean; timestamp: string; timestampTime?: string; coversWholeFile: boolean; error?: string; }

@Component({
  selector: 'app-root',
  template: `
    <h1>Signing spike</h1>
    <p class="muted">Flow: coordination complete → <b>Sign</b> → signer 1 (DO) → signer 2 (IO) → signed document.
      Provider: <b>{{ signer.name }}</b>.</p>

    @if (!doc()) {
      <button (click)="create()">1. Create sample document (coordination completed)</button>
    } @else {
      <section>
        <h2>{{ doc()!.title }}</h2>
        <p>Status: <b>{{ doc()!.status }}</b> · version {{ doc()!.version }}</p>
        <ol>
          @for (s of doc()!.signers; track s.role) {
            <li [class.done]="s.status === 'SIGNED'">
              <b>{{ s.role }}</b> — {{ s.status }}
              @if (s.subject) { <span class="muted"> · {{ s.subject }} · {{ s.signedAt }}</span> }
            </li>
          }
        </ol>

        @if (next()) {
          <button (click)="sign()" [disabled]="busy()">Sign as {{ next()!.role }} (AutoFirma)</button>
          <details>
            <summary>No AutoFirma? Test manually</summary>
            <p class="muted">Download the current PDF, sign it with any tool (e.g. the DevSigner or Adobe), upload the result.</p>
            <a [href]="pdfUrl()" target="_blank">Download current PDF (v{{ doc()!.version }})</a><br>
            <input type="file" accept="application/pdf" (change)="upload($event)">
          </details>
        } @else {
          <p class="ok">Document fully signed.</p>
        }
        <a [href]="pdfUrl()" target="_blank">Open current PDF</a>
        <button class="link" (click)="reset()">New document</button>
      </section>
    }

    @if (message()) { <p [class]="messageKind()">{{ message() }}</p> }

    @if (sigs().length) {
      <h3>Signatures verified by the backend</h3>
      <table>
        <tr><th>#</th><th>Signer</th><th>Issuer (CA)</th><th>Integrity</th><th>Chain</th><th>Revocation (OCSP/CRL)</th><th>Timestamp</th><th>Whole file</th></tr>
        @for (s of sigs(); track $index) {
          <tr>
            <td>{{ $index + 1 }}</td><td>{{ s.subject }}</td><td>{{ s.issuer }}</td>
            <td>{{ s.integrityOk ? '✔' : '✘' }}</td><td>{{ s.chainOk ? '✔' : '✘' }}</td><td>{{ s.revocationOk ? '✔' : '✘' }} {{ s.revocation }}</td><td>{{ s.timestampOk ? '✔' : '✘' }} {{ s.timestamp }} {{ s.timestampTime }}</td><td>{{ s.coversWholeFile ? '✔' : '✘' }}</td>
          </tr>
        }
      </table>
    }
  `,
  styles: [`
    :host { display: block; max-width: 760px; margin: 2rem auto; font-family: system-ui, sans-serif; padding: 0 1rem; }
    button { padding: .6rem 1rem; margin: .5rem .5rem .5rem 0; cursor: pointer; }
    button.link { background: none; border: none; color: #06c; text-decoration: underline; }
    .muted { color: #666; font-size: .9rem; }
    .done { color: #176f2c; }
    .ok { color: #176f2c; font-weight: 600; }
    .err { color: #b00020; }
    .info { color: #333; }
    table { border-collapse: collapse; width: 100%; font-size: .9rem; }
    td, th { border: 1px solid #ccc; padding: .3rem .5rem; text-align: left; }
  `],
})
export class App {
  // To switch provider tomorrow (remote QTSP, server seal) only this line changes.
  protected readonly signer: SigningService = new AutoFirmaSigner();

  protected readonly doc = signal<Doc | null>(null);
  protected readonly sigs = signal<SigInfo[]>([]);
  protected readonly message = signal('');
  protected readonly messageKind = signal<'info' | 'err' | 'ok'>('info');
  protected readonly busy = signal(false);
  protected readonly next = computed(() => this.doc()?.signers.find((s) => s.status === 'PENDING') ?? null);
  protected readonly pdfUrl = computed(() => `${API}/documents/${this.doc()?.id}/pdf?v=${this.doc()?.version}`);

  async create() {
    this.doc.set(await (await fetch(`${API}/documents`, { method: 'POST' })).json());
    this.sigs.set([]);
    this.say('Document created and frozen. Nobody may regenerate it from now on.', 'info');
  }

  reset() { this.doc.set(null); this.sigs.set([]); this.message.set(''); }

  async sign() {
    const d = this.doc()!;
    this.busy.set(true);
    try {
      this.say('Downloading the current version…', 'info');
      const res = await fetch(`${API}/documents/${d.id}/pdf`);
      const baseVersion = Number(res.headers.get('X-Version'));
      const pdf = await res.arrayBuffer();

      this.say('Waiting for AutoFirma (choose certificate and enter PIN)…', 'info');
      const turn = this.next()!;
      const signed = await this.signer.signPdf(pdf, {
        reason: `Signature as ${turn.role}`,
        role: turn.role,
        box: turn.box, // the PDF template decides where each role signs
      });
      await this.submit(d.id, baseVersion, signed);
    } catch (e: any) {
      this.say(`Signing failed: ${e?.message ?? e}`, 'err');
    } finally {
      this.busy.set(false);
    }
  }

  async upload(ev: Event) {
    const file = (ev.target as HTMLInputElement).files?.[0];
    if (!file) return;
    const d = this.doc()!;
    try {
      await this.submit(d.id, d.version, await file.arrayBuffer());
    } catch (e: any) {
      this.say(`Upload failed: ${e?.message ?? e}`, 'err');
    }
  }

  private async submit(id: string, baseVersion: number, pdf: ArrayBuffer) {
    this.say('Sending to the backend for verification…', 'info');
    const res = await fetch(`${API}/documents/${id}/sign?baseVersion=${baseVersion}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/pdf' },
      body: pdf,
    });
    const body = await res.json();
    this.sigs.set(body.signatures ?? []);
    if (!res.ok) {
      this.say(`Rejected by the backend: ${body.error}`, 'err');
      return;
    }
    this.doc.set(body.document);
    this.say(body.document.status === 'COMPLETED' ? 'All signatures collected and verified.' : 'Signature verified. Waiting for the next signer.', 'ok');
  }

  private say(m: string, k: 'info' | 'err' | 'ok') { this.message.set(m); this.messageKind.set(k); }
}
