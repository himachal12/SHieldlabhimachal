/**
 * API client for ShieldLabs backend
 * All calls go through axios with base URL configured
 */

import axios from 'axios'

const api = axios.create({
  baseURL: '/api',  // proxied to localhost:8000 via vite config
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  }
})

// ── Scan endpoints ──────────────────────────────────────

export const startCodeScan = (repoUrl) =>
  api.post('/scan/code', {
    repo_url: repoUrl,
    scan_type: 'code'
  })

export const startWebScan = (domain, scanMode = 'passive', consentConfirmed = false, activeUrls = []) =>
  api.post('/scan/web', {
    domain,
    scan_mode: scanMode,
    consent_confirmed: consentConfirmed,
    active_urls: activeUrls
  })

export const startCombinedScan = (
  repoUrl,
  domain,
  scanMode = 'passive',
  consentConfirmed = false,
  activeUrls = []
) =>
  api.post('/scan/combined', {
    repo_url: repoUrl,
    domain,
    scan_mode: scanMode,
    consent_confirmed: consentConfirmed,
    active_urls: activeUrls
  })

// ── Status + results ────────────────────────────────────

export const getScanStatus = (scanId) =>
  api.get(`/status/${scanId}`)

export const getScanResults = (scanId) =>
  api.get(`/results/${scanId}`)

export const getHealth = () =>
  api.get('/health')

export const getThreatIntel = (params = {}) =>
  api.get('/threat-intel', { params })

export default api