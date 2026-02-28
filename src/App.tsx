import React, { useEffect, useMemo, useState } from 'react'
import './App.css'

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none' | 'unknown'

type Cve = {
  id: string
  summary?: string
  score?: number
  severity?: Severity
  fixedIn?: string | string[]
  source?: string
}

type Dependency = {
  name: string
  version?: string
  cves: Cve[]
}

type RepoReport = {
  id: string
  name: string
  dependencies: Dependency[]
}

type DependencyWithStats = Dependency & {
  maxScore: number
  severity: Severity
  fixVersion: string | null
  cveCount: number
}

type RepoWithStats = RepoReport & {
  dependencies: DependencyWithStats[]
  repoSeverity: Severity
  repoMaxScore: number
  dependencyCount: number
  cveCount: number
}

type RepoSortKey = 'severity' | 'maxScore' | 'name'
type DependencySortKey = 'severity' | 'maxScore' | 'name'

type RepoSource = {
  id: string
  label: string
  url: string
}

const REPO_SOURCES: RepoSource[] = [
  {
    id: 'repo-1',
    label: 'Repository 1',
    url: '/reports/repo-1.json',
  },
  {
    id: 'repo-2',
    label: 'Repository 2',
    url: '/reports/repo-2.json',
  },
  {
    id: 'repo-3',
    label: 'Repository 3',
    url: '/reports/repo-3.json',
  },
]

const SEVERITY_ORDER: Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'none',
  'unknown',
]

function scoreToSeverity(score?: number): Severity {
  if (score == null || Number.isNaN(score)) {
    return 'unknown'
  }
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'none'
}

function normalizeSeverity(value?: string | Severity, score?: number): Severity {
  if (value) {
    const normalized = String(value).toLowerCase() as Severity
    if (SEVERITY_ORDER.includes(normalized)) return normalized
  }
  return scoreToSeverity(score)
}

function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b)
}

function compareVersions(a: string, b: string): number {
  const split = (v: string) => v.split('.').map((part) => Number.parseInt(part, 10) || 0)
  const aParts = split(a)
  const bParts = split(b)
  const maxLen = Math.max(aParts.length, bParts.length)

  for (let i = 0; i < maxLen; i += 1) {
    const aNum = aParts[i] ?? 0
    const bNum = bParts[i] ?? 0
    if (aNum !== bNum) {
      return aNum - bNum
    }
  }

  return 0
}

function toArray<T>(value: T | T[] | undefined | null): T[] {
  if (value == null) return []
  return Array.isArray(value) ? value : [value]
}

function buildDependencyStats(dep: Dependency): DependencyWithStats {
  let maxScore = 0
  let derivedSeverity: Severity = 'none'
  const allFixedVersions: string[] = []

  dep.cves.forEach((cve) => {
    const score = cve.score ?? 0
    if (score > maxScore) {
      maxScore = score
    }
    const cveSeverity = normalizeSeverity(cve.severity, cve.score)
    if (compareSeverity(cveSeverity, derivedSeverity) < 0 || derivedSeverity === 'none') {
      derivedSeverity = cveSeverity
    }
    const fixed = toArray(cve.fixedIn)
    fixed.forEach((v) => {
      if (typeof v === 'string' && v.trim()) {
        allFixedVersions.push(v.trim())
      }
    })
  })

  let fixVersion: string | null = null
  if (allFixedVersions.length > 0) {
    fixVersion = allFixedVersions.sort((a, b) => compareVersions(a, b))[allFixedVersions.length - 1]
  }

  if (dep.cves.length === 0) {
    derivedSeverity = 'none'
  }

  return {
    ...dep,
    maxScore,
    severity: derivedSeverity,
    fixVersion,
    cveCount: dep.cves.length,
  }
}

function buildRepoStats(base: RepoReport): RepoWithStats {
  const dependenciesWithStats = base.dependencies.map(buildDependencyStats)

  let repoMaxScore = 0
  let repoSeverity: Severity = 'none'
  let cveCount = 0

  dependenciesWithStats.forEach((dep) => {
    if (dep.maxScore > repoMaxScore) {
      repoMaxScore = dep.maxScore
    }
    if (compareSeverity(dep.severity, repoSeverity) < 0 || repoSeverity === 'none') {
      repoSeverity = dep.severity
    }
    cveCount += dep.cveCount
  })

  if (dependenciesWithStats.length === 0) {
    repoSeverity = 'none'
  }

  return {
    ...base,
    dependencies: dependenciesWithStats,
    repoSeverity,
    repoMaxScore,
    dependencyCount: dependenciesWithStats.length,
    cveCount,
  }
}

function sortRepos(repos: RepoWithStats[], key: RepoSortKey): RepoWithStats[] {
  const copy = [...repos]
  copy.sort((a, b) => {
    if (key === 'name') {
      return a.name.localeCompare(b.name)
    }

    if (key === 'severity') {
      const severityCompare = compareSeverity(a.repoSeverity, b.repoSeverity)
      if (severityCompare !== 0) return severityCompare
      if (b.repoMaxScore !== a.repoMaxScore) {
        return b.repoMaxScore - a.repoMaxScore
      }
      return a.name.localeCompare(b.name)
    }

    if (b.repoMaxScore !== a.repoMaxScore) {
      return b.repoMaxScore - a.repoMaxScore
    }

    const severityCompare = compareSeverity(a.repoSeverity, b.repoSeverity)
    if (severityCompare !== 0) return severityCompare

    return a.name.localeCompare(b.name)
  })
  return copy
}

function sortDependencies(
  dependencies: DependencyWithStats[],
  key: DependencySortKey,
): DependencyWithStats[] {
  const copy = [...dependencies]
  copy.sort((a, b) => {
    if (key === 'name') {
      return a.name.localeCompare(b.name)
    }

    if (key === 'severity') {
      const severityCompare = compareSeverity(a.severity, b.severity)
      if (severityCompare !== 0) return severityCompare
      if (b.maxScore !== a.maxScore) {
        return b.maxScore - a.maxScore
      }
      return a.name.localeCompare(b.name)
    }

    if (b.maxScore !== a.maxScore) {
      return b.maxScore - a.maxScore
    }

    const severityCompare = compareSeverity(a.severity, b.severity)
    if (severityCompare !== 0) return severityCompare

    return a.name.localeCompare(b.name)
  })
  return copy
}

function formatSeverityLabel(severity: Severity): string {
  if (severity === 'none') return 'No issues'
  if (severity === 'unknown') return 'Unknown'
  return severity.charAt(0).toUpperCase() + severity.slice(1)
}

function formatScore(score: number | undefined | null): string {
  if (score == null || Number.isNaN(score)) return '-'
  return score.toFixed(1)
}

function formatFixVersion(version: string | null | undefined): string {
  if (!version) return '-'
  return version
}

function App() {
  const [reports, setReports] = useState<RepoWithStats[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [repoSort, setRepoSort] = useState<RepoSortKey>('severity')
  const [dependencySort, setDependencySort] = useState<DependencySortKey>('severity')
  const [expandedRepos, setExpandedRepos] = useState<Set<string>>(new Set())
  const [expandedDependencies, setExpandedDependencies] = useState<Set<string>>(new Set())

  useEffect(() => {
    let cancelled = false

    async function load() {
      try {
        setLoading(true)
        setError(null)

        const fetchedReports: RepoWithStats[] = []
        const errors: string[] = []

        // Load all configured repositories in parallel
        await Promise.all(
          REPO_SOURCES.map(async (source) => {
            try {
              const response = await fetch(source.url)

              if (!response.ok) {
                throw new Error(
                  `Could not load JSON (status ${response.status}). Check that the file exists at ${source.url}.`,
                )
              }

              const contentType = response.headers.get('content-type') ?? ''
              if (!contentType.toLowerCase().includes('application/json')) {
                throw new Error(
                  'Response is not JSON. In Vite dev, a missing file often returns the index.html fallback – please verify the JSON path.',
                )
              }

              let raw: unknown
              try {
                raw = (await response.json()) as unknown
              } catch (parseError) {
                throw new Error(
                  'Invalid JSON content. Ensure the report file is valid JSON (no HTML or extra text).',
                )
              }

              const repoReport = normalizeRawReport(raw, source)
              fetchedReports.push(buildRepoStats(repoReport))
            } catch (innerError) {
              const message =
                innerError instanceof Error ? innerError.message : 'Unknown error loading reports'
              errors.push(`${source.label}: ${message}`)
            }
          }),
        )

        if (!cancelled) {
          setReports(fetchedReports)
          setError(errors.length > 0 ? errors.join('\n') : null)
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    load()

    return () => {
      cancelled = true
    }
  }, [])

  const sortedReports = useMemo(() => sortRepos(reports, repoSort), [reports, repoSort])

  const summary = useMemo(() => {
    if (reports.length === 0) {
      return {
        totalRepos: 0,
        totalDependencies: 0,
        totalCves: 0,
        highestSeverity: 'none' as Severity,
        highestScore: 0,
      }
    }

    let totalDependencies = 0
    let totalCves = 0
    let highestSeverity: Severity = 'none'
    let highestScore = 0

    reports.forEach((repo) => {
      totalDependencies += repo.dependencyCount
      totalCves += repo.cveCount
      if (compareSeverity(repo.repoSeverity, highestSeverity) < 0 || highestSeverity === 'none') {
        highestSeverity = repo.repoSeverity
      }
      if (repo.repoMaxScore > highestScore) {
        highestScore = repo.repoMaxScore
      }
    })

    return {
      totalRepos: reports.length,
      totalDependencies,
      totalCves,
      highestSeverity,
      highestScore,
    }
  }, [reports])

  const toggleRepo = (id: string) => {
    setExpandedRepos((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  const toggleDependency = (repoId: string, depName: string) => {
    const key = `${repoId}::${depName}`
    setExpandedDependencies((prev) => {
      const next = new Set(prev)
      if (next.has(key)) {
        next.delete(key)
      } else {
        next.add(key)
      }
      return next
    })
  }

  return (
    <div className="dashboard-root">
      <header className="dashboard-header">
        <div>
          <p className="dashboard-kicker">OpenMRS · Security</p>
          <h1 className="dashboard-title">Dependency Vulnerability Dashboard</h1>
        </div>
        <div className="dashboard-header-controls">
          <div className="dashboard-sort">
            <span className="dashboard-sort-label">Sort repositories by</span>
            <select
              value={repoSort}
              onChange={(event) => setRepoSort(event.target.value as RepoSortKey)}
            >
              <option value="severity">Repo severity</option>
              <option value="maxScore">Highest CVE score</option>
              <option value="name">Repo name (A–Z)</option>
            </select>
          </div>
        </div>
      </header>

      <main className="dashboard-main">
        <section className="dashboard-summary">
          <SummaryCard
            label="Repositories"
            primary={summary.totalRepos.toString()}
            secondary="scanned from JSON reports"
          />
          <SummaryCard
            label="Dependencies with issues"
            primary={summary.totalDependencies.toString()}
            secondary="across all repositories"
          />
          <SummaryCard
            label="CVEs"
            primary={summary.totalCves.toString()}
            secondary="linked to dependencies"
          />
          <SummaryCard
            label="Highest severity"
            primary={formatSeverityLabel(summary.highestSeverity)}
            secondary={
              summary.highestScore > 0 ? `Max CVSS score ${formatScore(summary.highestScore)}` : '-'
            }
            severity={summary.highestSeverity}
          />
        </section>

        {loading && (
          <div className="dashboard-panel dashboard-panel--muted">
            <p>Loading reports…</p>
          </div>
        )}

        {error && (
          <div className="dashboard-alert">
            <span className="dashboard-alert-title">Some reports could not be loaded</span>
            <pre className="dashboard-alert-body">{error}</pre>
          </div>
        )}

        {!loading && sortedReports.length === 0 && !error && (
          <div className="dashboard-panel dashboard-panel--muted">
            <p>No reports found. Make sure your JSON files are placed under `/public/reports`.</p>
          </div>
        )}

        {sortedReports.map((repo) => {
          const isExpanded = expandedRepos.has(repo.id)
          const sortedDependencies = sortDependencies(repo.dependencies, dependencySort)

          return (
            <section key={repo.id} className="repo-card">
              <button
                type="button"
                className="repo-card-header"
                onClick={() => toggleRepo(repo.id)}
              >
                <div className="repo-card-header-main">
                  <span className="repo-name">{repo.name}</span>
                  <span className={`severity-pill severity-pill--${repo.repoSeverity}`}>
                    {formatSeverityLabel(repo.repoSeverity)}
                  </span>
                </div>
                <div className="repo-card-header-meta">
                  <span>{repo.dependencyCount} dependencies</span>
                  <span>{repo.cveCount} CVEs</span>
                  <span>Max score {formatScore(repo.repoMaxScore)}</span>
                </div>
                <span className="repo-card-header-toggle" aria-hidden="true">
                  {isExpanded ? '▾' : '▸'}
                </span>
              </button>

              {isExpanded && (
                <div className="repo-card-body">
                  <div className="repo-card-toolbar">
                    <div className="repo-card-toolbar-group">
                      <span className="toolbar-label">Dependencies</span>
                      <span className="toolbar-helper">
                        Severity is derived from the highest CVE score in each dependency.
                      </span>
                    </div>
                    <div className="dashboard-sort">
                      <span className="dashboard-sort-label">Sort dependencies by</span>
                      <select
                        value={dependencySort}
                        onChange={(event) =>
                          setDependencySort(event.target.value as DependencySortKey)
                        }
                      >
                        <option value="severity">Dependency severity</option>
                        <option value="maxScore">Highest CVE score</option>
                        <option value="name">Name (A–Z)</option>
                      </select>
                    </div>
                  </div>

                  <div className="table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Dependency</th>
                          <th>Installed</th>
                          <th>Severity</th>
                          <th>Highest CVE score</th>
                          <th>Fix version</th>
                          <th>CVEs</th>
                        </tr>
                      </thead>
                      <tbody>
                        {sortedDependencies.map((dep) => {
                          const key = `${repo.id}::${dep.name}`
                          const depExpanded = expandedDependencies.has(key)
                          return (
                            <React.Fragment key={key}>
                              <tr
                                className="dependency-row"
                                onClick={() => toggleDependency(repo.id, dep.name)}
                              >
                                <td>
                                  <div className="dependency-name">{dep.name}</div>
                                </td>
                                <td>{dep.version ?? '-'}</td>
                                <td>
                                  <span
                                    className={`severity-pill severity-pill--${dep.severity}`}
                                  >
                                    {formatSeverityLabel(dep.severity)}
                                  </span>
                                </td>
                                <td>{formatScore(dep.maxScore)}</td>
                                <td>{formatFixVersion(dep.fixVersion)}</td>
                                <td>{dep.cveCount}</td>
                              </tr>
                              {depExpanded && (
                                <tr className="dependency-cves-row">
                                  <td colSpan={6}>
                                    <CveTable cves={dep.cves} />
                                  </td>
                                </tr>
                              )}
                            </React.Fragment>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </section>
          )
        })}
      </main>
    </div>
  )
}

type SummaryCardProps = {
  label: string
  primary: string
  secondary?: string
  severity?: Severity
}

function SummaryCard({ label, primary, secondary, severity }: SummaryCardProps) {
  return (
    <article className="summary-card">
      <p className="summary-card-label">{label}</p>
      <p className="summary-card-primary">{primary}</p>
      {severity ? (
        <span className={`severity-pill severity-pill--${severity} summary-card-pill`}>
          {formatSeverityLabel(severity)}
        </span>
      ) : null}
      {secondary ? <p className="summary-card-secondary">{secondary}</p> : null}
    </article>
  )
}

type CveTableProps = {
  cves: Cve[]
}

function CveTable({ cves }: CveTableProps) {
  const sorted = useMemo(
    () => [...cves].sort((a, b) => (b.score ?? 0) - (a.score ?? 0)),
    [cves],
  )

  if (sorted.length === 0) {
    return <p className="empty-state">No CVEs linked to this dependency.</p>
  }

  return (
    <div>
      <div className="cve-table-header">
        <span className="toolbar-label">CVEs</span>
        <span className="toolbar-helper">Sorted by score (highest first).</span>
      </div>
      <div className="table-wrapper table-wrapper--embedded">
        <table className="data-table data-table--compact">
          <thead>
            <tr>
              <th>ID</th>
              <th>Score</th>
              <th>Severity</th>
              <th>Description</th>
              <th>Fixed in</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((cve) => (
              <tr key={cve.id}>
                <td className="cve-id">{cve.id}</td>
                <td>{formatScore(cve.score)}</td>
                <td>
                  <span
                    className={`severity-pill severity-pill--${normalizeSeverity(
                      cve.severity,
                      cve.score,
                    )}`}
                  >
                    {formatSeverityLabel(normalizeSeverity(cve.severity, cve.score))}
                  </span>
                </td>
                <td className="cve-summary">{cve.summary ?? '-'}</td>
                <td>{formatFixVersion(toArray(cve.fixedIn)[0])}</td>
                <td>{cve.source ?? '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function normalizeRawReport(raw: unknown, source: RepoSource): RepoReport {
  const data = raw as Record<string, unknown>

  const name =
    (typeof data.name === 'string' && data.name) ||
    (typeof data.repo === 'string' && data.repo) ||
    (typeof data.repository === 'string' && data.repository) ||
    source.label

  const dependenciesRaw = (data.dependencies as unknown) ?? []
  const depsArray = Array.isArray(dependenciesRaw) ? dependenciesRaw : []

  const dependencies: Dependency[] = []

  if (depsArray.length > 0) {
    // Generic format with explicit dependencies array
    depsArray.forEach((item) => {
      const dep = item as Record<string, unknown>
      const nameValue =
        (typeof dep.name === 'string' && dep.name) ||
        (typeof dep.package === 'string' && dep.package) ||
        'Unknown dependency'

      const versionValue =
        (typeof dep.version === 'string' && dep.version) ||
        (typeof dep.currentVersion === 'string' && dep.currentVersion) ||
        undefined

      const cvesRaw = (dep.cves ?? dep.vulnerabilities) as unknown
      const cvesArr = Array.isArray(cvesRaw) ? cvesRaw : []
      const cves: Cve[] = []

      cvesArr.forEach((cveRaw) => {
        const cve = cveRaw as Record<string, unknown>
        const id =
          (typeof cve.id === 'string' && cve.id) ||
          (typeof cve.cveId === 'string' && cve.cveId) ||
          (typeof cve.identifier === 'string' && cve.identifier)

        if (!id) return

        const numericScore =
          typeof cve.score === 'number'
            ? cve.score
            : typeof cve.cvssScore === 'number'
              ? cve.cvssScore
              : typeof cve.cvssScore === 'string'
                ? Number.parseFloat(cve.cvssScore)
                : undefined

        const severity =
          (typeof cve.severity === 'string' && (cve.severity as Severity)) ||
          (typeof cve.cvssSeverity === 'string' && (cve.cvssSeverity as Severity)) ||
          undefined

        const fixedIn =
          cve.fixedIn ??
          cve.fixed_in ??
          cve.fixedVersion ??
          cve.fixedVersions ??
          cve.patchedVersions

        const sourceField =
          (typeof cve.source === 'string' && cve.source) ||
          (typeof cve.url === 'string' && cve.url) ||
          undefined

        cves.push({
          id,
          summary:
            (typeof cve.summary === 'string' && cve.summary) ||
            (typeof cve.description === 'string' && cve.description) ||
            undefined,
          score: numericScore,
          severity: severity ? normalizeSeverity(severity, numericScore) : undefined,
          fixedIn: fixedIn as string | string[] | undefined,
          source: sourceField,
        })
      })

      dependencies.push({
        name: nameValue,
        version: versionValue,
        cves,
      })
    })
  } else {
    // GitLab dependency-scanning style: vulnerabilities array with location.dependency.package
    const vulnerabilitiesRaw = (data.vulnerabilities as unknown) ?? []
    const vulnerabilities = Array.isArray(vulnerabilitiesRaw) ? vulnerabilitiesRaw : []

    const depsByKey = new Map<string, Dependency>()

    const approximateScoreBySeverity: Record<Severity, number> = {
      critical: 9.8,
      high: 8.0,
      medium: 6.0,
      low: 3.0,
      none: 0,
      unknown: 0,
    }

    vulnerabilities.forEach((vulnRaw) => {
      const vuln = vulnRaw as Record<string, unknown>
      const location = vuln.location as Record<string, unknown> | undefined
      const dependencyInfo = (location?.dependency as Record<string, unknown> | undefined) ?? {}
      const packageInfo = (dependencyInfo.package as Record<string, unknown> | undefined) ?? {}

      const pkgName =
        (typeof packageInfo.name === 'string' && packageInfo.name) ||
        (typeof dependencyInfo.name === 'string' && dependencyInfo.name)

      if (!pkgName) {
        return
      }

      const versionValue =
        (typeof dependencyInfo.version === 'string' && dependencyInfo.version) || undefined

      const key = `${pkgName}@${versionValue ?? 'unknown'}`

      let dep = depsByKey.get(key)
      if (!dep) {
        dep = {
          name: pkgName,
          version: versionValue,
          cves: [],
        }
        depsByKey.set(key, dep)
      }

      const identifiersRaw = (vuln.identifiers as unknown) ?? []
      const identifiers = Array.isArray(identifiersRaw) ? identifiersRaw : []

      let derivedId: string | undefined =
        (typeof vuln.id === 'string' && vuln.id) ||
        (typeof vuln.name === 'string' && vuln.name) ||
        undefined

      if (!derivedId) {
        const cveIdentifier = identifiers.find((item) => {
          const obj = item as Record<string, unknown>
          const type = typeof obj.type === 'string' ? obj.type : ''
          const name = typeof obj.name === 'string' ? obj.name : ''
          return type.toUpperCase().includes('CVE') || name.toUpperCase().startsWith('CVE-')
        }) as Record<string, unknown> | undefined

        if (cveIdentifier) {
          const name = typeof cveIdentifier.name === 'string' ? cveIdentifier.name : undefined
          const value = typeof cveIdentifier.value === 'string' ? cveIdentifier.value : undefined
          derivedId = name ?? value
        }
      }

      if (!derivedId) {
        return
      }

      const severityRaw = typeof vuln.severity === 'string' ? vuln.severity : undefined
      const normalizedSeverity = normalizeSeverity(
        severityRaw?.toLowerCase() as Severity | undefined,
        undefined,
      )
      const numericScore = approximateScoreBySeverity[normalizedSeverity]

      const linksRaw = (vuln.links as unknown) ?? []
      const links = Array.isArray(linksRaw) ? linksRaw : []
      const firstLink = links[0] as Record<string, unknown> | undefined
      const linkUrl =
        (firstLink && typeof firstLink.url === 'string' && firstLink.url) || undefined

      const cve: Cve = {
        id: derivedId,
        summary:
          (typeof vuln.description === 'string' && vuln.description) ||
          (typeof vuln.message === 'string' && vuln.message) ||
          undefined,
        score: numericScore,
        severity: normalizedSeverity,
        fixedIn: undefined,
        source: linkUrl,
      }

      dep.cves.push(cve)
    })

    depsByKey.forEach((dep) => {
      dependencies.push(dep)
    })
  }

  return {
    id: source.id,
    name,
    dependencies,
  }
}

export default App
