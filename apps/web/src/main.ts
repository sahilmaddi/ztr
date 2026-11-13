import { bootstrapApplication } from '@angular/platform-browser';
import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import JSZip from 'jszip';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule],
  template: `
    <main class="shell">
      <header class="topbar">
        <a class="brand" href="/" aria-label="Batch 5 ZTR home"><span class="brand-mark">S</span><span>Batch 5 ZTR</span></a>
        <div class="topbar-meta"><span class="live-dot"></span> Local workspace <span class="divider"></span> v0.1 <button class="theme-button" type="button" (click)="toggleTheme()" [attr.aria-label]="darkMode ? 'Use light theme' : 'Use dark theme'" [attr.aria-pressed]="darkMode"><span>{{ darkMode ? '&#9788;' : '&#9790;' }}</span></button></div>
      </header>

      <section class="intro">
        <div class="eyebrow"><span class="eyebrow-line"></span> ZERO-TOUCH REGRESSION</div>
        <h1>Ship with<br><em>evidence.</em></h1>
        <p class="lede">Upload a project. Batch 5 ZTR runs a browser smoke test and an OWASP ZAP passive security scan, then reports each result separately.</p>
      </section>

      <section class="workspace" aria-label="Regression workspace">
        <div class="workspace-head">
          <div><span class="section-kicker">01 / PROJECT</span><h2>Choose a project package</h2></div>
          <span class="format-pill">ZIP only <span>200 MB max</span></span>
        </div>

        <label class="dropzone" [class.has-file]="file" for="project-file">
          <input id="project-file" type="file" accept=".zip,application/zip" (change)="selectFile($event)" />
          <span class="upload-icon" aria-hidden="true"><span></span></span>
          <span class="drop-title">{{ file ? file.name : 'Drop your project here' }}</span>
          <span class="drop-note">{{ file ? formatBytes(file.size) + ' ready for inspection' : 'or click to browse your files' }}</span>
        </label>

        <div class="scan-target">
          <label for="scan-target-url">Optional live Juice Shop target</label>
          <input id="scan-target-url" type="url" placeholder="http://juice-shop:3000" [value]="targetUrl" (input)="targetUrl = $any($event.target).value" />
          <small>Leave blank to scan only the static files in the uploaded ZIP. For the Compose lab, use http://juice-shop:3000.</small>
          <label class="active-toggle"><input type="checkbox" [checked]="activeScan" (change)="activeScan = $any($event.target).checked" /> Enable active ZAP scan (only for the local Juice Shop lab)</label>
        </div>

        <div class="action-row">
          <span class="helper-text" *ngIf="!file">A project ZIP with an <code>index.html</code> entry point works best.</span>
          <span class="helper-text selected" *ngIf="file"><span class="checkmark">&#10003;</span> Package selected</span>
          <button class="run-button" (click)="inspect()" [disabled]="!file || loading"><span class="button-orb"></span>{{ loading ? 'Running checks' : 'Run regression' }} <span class="arrow">&#8594;</span></button>
        </div>
        <p class="error" *ngIf="error"><strong>Run could not start.</strong> {{ error }}</p>
      </section>

      <section class="result result-panel" *ngIf="result">
        <div class="result-heading"><span class="section-kicker">02 / TEST REPORT</span><span class="result-status" [class.failed]="result.status === 'failed'" [class.incomplete]="result.status === 'incomplete'"><span></span>{{ result.status === 'passed' ? 'PASS' : result.status === 'incomplete' ? 'INCOMPLETE' : 'FAIL' }}</span></div>
        <div class="result-main"><div><h2>{{ result.fileName }}</h2><p>{{ result.fileCount }} project files inspected by {{ result.engine }}.</p></div><div class="result-score">{{ result.status === 'passed' ? 'OK' : result.status === 'incomplete' ? '!' : 'NO' }}<small>OVERALL</small></div></div>
        <div class="test-grid">
          <article class="test-card"><div class="test-card-head"><span>FUNCTIONAL REGRESSION</span><b [class.bad-text]="result.functionalStatus !== 'passed'">{{ result.functionalStatus === 'passed' ? 'PASS' : 'FAIL' }}</b></div><p>Browser launch and page-render smoke test using Selenium.</p><small *ngIf="result.title">Page title: {{ result.title }}</small><small class="bad-text" *ngIf="result.functionalError">{{ result.functionalError }}</small></article>
          <article class="test-card"><div class="test-card-head"><span>SECURITY SCAN</span><b [class.bad-text]="result.securityStatus === 'findings'" [class.warn-text]="result.securityStatus === 'not_run'">{{ result.securityStatus === 'passed' ? 'NO MEDIUM/HIGH ALERTS' : result.securityStatus === 'findings' ? 'FINDINGS DETECTED' : 'NOT COMPLETED' }}</b></div><p>{{ result.scanType }}</p><small>Target: {{ result.scanTarget }}</small><div class="risk-counts"><span>High <strong>{{ result.securityCounts?.high ?? 0 }}</strong></span><span>Medium <strong>{{ result.securityCounts?.medium ?? 0 }}</strong></span><span>Low <strong>{{ result.securityCounts?.low ?? 0 }}</strong></span><span>Info <strong>{{ result.securityCounts?.informational ?? 0 }}</strong></span></div><small class="bad-text" *ngIf="result.securityError">{{ result.securityError }}</small></article>
        </div>
        <div class="details"><div><span>ENTRY POINT</span><strong>{{ result.entryPoint || 'Not detected' }}</strong></div><div><span>BROWSER TITLE</span><strong>{{ result.title || 'Not available' }}</strong></div></div>
        <div class="alerts" *ngIf="result.securityAlerts?.length"><h3>Security alerts</h3><article *ngFor="let alert of result.securityAlerts" class="alert-row"><div><strong>{{ alert.name }}</strong><small>{{ alert.url }}</small></div><b [class.bad-text]="alert.risk === 'High' || alert.risk === 'Medium'">{{ alert.risk }}</b></article></div>
        <p class="scan-note">A PASS means this configured ZAP scan found no Medium/High-risk alerts. It does not prove the application is vulnerability-free. Active scanning sends test payloads; use it only against the isolated Juice Shop lab.</p>
      </section>

      <footer><span>Built for fast feedback</span><span class="footer-rule"></span><span>LangGraph / Selenium / OWASP ZAP passive scan</span></footer>
    </main>
  `,
})
class AppComponent {
  file?: File;
  loading = false;
  targetUrl = '';
  activeScan = false;
  darkMode = localStorage.getItem('batch5ztr-theme') === 'dark';
  result?: InspectionResult;
  error = '';

  constructor() {
    this.applyTheme();
  }

  selectFile(event: Event) {
    const input = event.target as HTMLInputElement;
    this.file = input.files?.[0];
    this.error = '';
  }

  formatBytes(bytes: number) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  }

  toggleTheme() {
    this.darkMode = !this.darkMode;
    localStorage.setItem('batch5ztr-theme', this.darkMode ? 'dark' : 'light');
    this.applyTheme();
  }

  private applyTheme() {
    document.body.classList.toggle('dark-theme', this.darkMode);
  }

  async inspect() {
    if (!this.file) return;
    this.loading = true;
    this.result = undefined;
    this.error = '';
    try {
      if (!this.file.name.toLowerCase().endsWith('.zip')) {
        throw new Error('Choose a ZIP containing the complete project.');
      }
      if (this.file.size > 200 * 1024 * 1024) {
        throw new Error('ZIP upload exceeds the 200 MB limit.');
      }
      const archive = await JSZip.loadAsync(this.file);
      const files = Object.keys(archive.files).filter(fileName => !archive.files[fileName].dir).sort();
      if (!files.some(fileName => fileName.endsWith('index.html'))) {
        throw new Error('The package must contain an index.html entry point.');
      }
      const response = await fetch('/regress', {
        method: 'POST',
        body: (() => {
          const data = new FormData();
          data.append('file', this.file!);
          if (this.targetUrl.trim()) data.append('target_url', this.targetUrl.trim());
          data.append('active_scan', String(this.activeScan));
          return data;
        })()
      });
      const responseText = await response.text();
      let body: InspectionResult & { detail?: string };
      try {
        body = JSON.parse(responseText) as InspectionResult & { detail?: string };
      } catch {
        throw new Error(`Regression service returned HTTP ${response.status}. The project ZIP may be too large.`);
      }
      if (!response.ok) throw new Error(body.detail ?? 'Regression failed.');
      this.result = body;
    } catch (error) {
      this.error = error instanceof Error ? error.message : 'The ZIP could not be inspected.';
    } finally {
      this.loading = false;
    }
  }
}

interface SecurityAlert {
  name: string;
  risk: string;
  url: string;
}

interface InspectionResult {
  fileName: string;
  status: 'passed' | 'failed' | 'incomplete';
  engine: string;
  fileCount: number;
  entryPoint?: string;
  title?: string;
  functionalStatus: string;
  functionalError?: string;
  securityStatus: 'passed' | 'findings' | 'not_run';
  securityError?: string;
  securityCounts?: { high: number; medium: number; low: number; informational: number };
  securityAlerts?: SecurityAlert[];
  scanType?: string;
  scanTarget?: string;
  activeScan?: boolean;
}

bootstrapApplication(AppComponent);