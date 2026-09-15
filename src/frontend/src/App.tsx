// Main App — layout, routing, state management

import { useState, useEffect, useCallback } from 'react'
import type { Alert, DashboardStats, ThreatIntel } from './types'
import { api } from './api'
import { StatsBar } from './components/StatsBar'
import { AlertCard } from './components/AlertCard'
import { AlertDetail } from './components/AlertDetail'
import { RiskChart } from './components/RiskChart'
import { ThreatIntelPanel } from './components/ThreatIntelPanel'

type Tab = 'dashboard' | 'alerts' | 'intel' | 'correlations'

type Filter = 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export default function App() {
  const [tab, setTab] = useState<Tab>('dashboard')
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [threats, setThreats] = useState<ThreatIntel[]>([])
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [filter, setFilter] = useState<Filter>('ALL')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // ─────────────────────────────────────────────────────────────
  // Load dashboard data
  // ─────────────────────────────────────────────────────────────

  const loadData = useCallback(async () => {
    setLoading(true)
    setError(null)

    try {
      const [s, a, t] = await Promise.all([
        api.getDashboard(),
        api.getAlerts(),
        api.getThreats(),
      ])

      setStats(s)
      setAlerts(a)
      setThreats(t)
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : 'Failed to load data'
      )
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadData()
  }, [loadData])

  // ─────────────────────────────────────────────────────────────
  // Alert actions
  // ─────────────────────────────────────────────────────────────

  const handleAcknowledge = async (id: number) => {
    try {
      const updated = await api.acknowledgeAlert(id)

      setAlerts(prev =>
        prev.map(a =>
          a.id === id ? updated : a
        )
      )

      if (selectedAlert?.id === id) {
        setSelectedAlert(updated)
      }

      await loadData()
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : 'Failed to acknowledge alert'
      )
    }
  }

  const handleFalsePositive = async (id: number) => {
    try {
      const updated = await api.markFalsePositive(id)

      setAlerts(prev =>
        prev.map(a =>
          a.id === id ? updated : a
        )
      )

      setSelectedAlert(null)

      await loadData()
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : 'Failed to mark alert as false positive'
      )
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Navigation handlers
  // ─────────────────────────────────────────────────────────────

  const openAlertFilter = (nextFilter: Filter) => {
    setFilter(nextFilter)
    setSelectedAlert(null)
    setTab('alerts')
  }

  const openCorrelations = () => {
    setSelectedAlert(null)
    setTab('correlations')
  }

  const openDashboard = () => {
    setSelectedAlert(null)
    setTab('dashboard')
  }

  const openAlerts = () => {
    setSelectedAlert(null)
    setFilter('ALL')
    setTab('alerts')
  }

  const openThreatIntel = () => {
    setSelectedAlert(null)
    setTab('intel')
  }

  // ─────────────────────────────────────────────────────────────
  // Filter alerts
  // ─────────────────────────────────────────────────────────────

  const filteredAlerts = alerts.filter(a =>
    (filter === 'ALL' || a.risk_level === filter) &&
    !a.is_false_positive
  )

  const FILTERS: Filter[] = [
    'ALL',
    'CRITICAL',
    'HIGH',
    'MEDIUM',
    'LOW',
  ]

  const FILTER_LABELS: Record<Filter, string> = {
    ALL: 'All',
    CRITICAL: '🔴 Critical',
    HIGH: '🟠 High',
    MEDIUM: '🟡 Medium',
    LOW: '🟢 Low',
  }

  // ─────────────────────────────────────────────────────────────
  // Correlation groups
  // ─────────────────────────────────────────────────────────────

  const correlationGroups = Array.from(
    new Set(
      alerts
        .filter(a => !a.is_false_positive)
        .map(a => a.correlation_group_id)
        .filter(Boolean)
    )
  )

  // ─────────────────────────────────────────────────────────────
  // Render
  // ─────────────────────────────────────────────────────────────

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
      }}
    >

      {/* ─────────────────────────────────────────────────────────
          Navbar
      ───────────────────────────────────────────────────────── */}

      <nav
        style={{
          background: 'var(--surface)',
          borderBottom: '1px solid var(--border)',
          padding: '0 24px',
          display: 'flex',
          alignItems: 'center',
          height: 52,
          position: 'sticky',
          top: 0,
          zIndex: 50,
        }}
      >
        {/* Logo */}

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            marginRight: 32,
          }}
        >
          <span style={{ fontSize: 20 }}>
            🛡
          </span>

          <span
            style={{
              fontWeight: 700,
              fontSize: 16,
              color: 'var(--text)',
            }}
          >
            ThreatNexus
          </span>

          <span
            style={{
              fontSize: 10,
              background: '#1f6feb33',
              color: '#58a6ff',
              border: '1px solid #1f6feb',
              borderRadius: 3,
              padding: '1px 6px',
            }}
          >
            AI-Powered
          </span>
        </div>

        {/* Navigation */}

        <div
          style={{
            display: 'flex',
            gap: 4,
          }}
        >
          <button
            type="button"
            onClick={openDashboard}
            style={{
              background:
                tab === 'dashboard'
                  ? 'var(--surface-2)'
                  : 'transparent',
              border: 'none',
              color:
                tab === 'dashboard'
                  ? 'var(--text)'
                  : 'var(--muted)',
              padding: '6px 14px',
              borderRadius: 6,
              fontSize: 13,
              fontWeight:
                tab === 'dashboard'
                  ? 600
                  : 400,
              cursor: 'pointer',
            }}
          >
            📊 Dashboard
          </button>

          <button
            type="button"
            onClick={openAlerts}
            style={{
              background:
                tab === 'alerts'
                  ? 'var(--surface-2)'
                  : 'transparent',
              border: 'none',
              color:
                tab === 'alerts'
                  ? 'var(--text)'
                  : 'var(--muted)',
              padding: '6px 14px',
              borderRadius: 6,
              fontSize: 13,
              fontWeight:
                tab === 'alerts'
                  ? 600
                  : 400,
              cursor: 'pointer',
            }}
          >
            🚨 Alerts
          </button>

          <button
            type="button"
            onClick={openThreatIntel}
            style={{
              background:
                tab === 'intel'
                  ? 'var(--surface-2)'
                  : 'transparent',
              border: 'none',
              color:
                tab === 'intel'
                  ? 'var(--text)'
                  : 'var(--muted)',
              padding: '6px 14px',
              borderRadius: 6,
              fontSize: 13,
              fontWeight:
                tab === 'intel'
                  ? 600
                  : 400,
              cursor: 'pointer',
            }}
          >
            🔍 Threat Intel
          </button>

          <button
            type="button"
            onClick={openCorrelations}
            style={{
              background:
                tab === 'correlations'
                  ? 'var(--surface-2)'
                  : 'transparent',
              border: 'none',
              color:
                tab === 'correlations'
                  ? 'var(--text)'
                  : 'var(--muted)',
              padding: '6px 14px',
              borderRadius: 6,
              fontSize: 13,
              fontWeight:
                tab === 'correlations'
                  ? 600
                  : 400,
              cursor: 'pointer',
            }}
          >
            🔗 Correlations
          </button>
        </div>

        {/* Refresh */}

        <div
          style={{
            marginLeft: 'auto',
          }}
        >
          <button
            type="button"
            onClick={loadData}
            style={{
              background: 'transparent',
              border: '1px solid var(--border)',
              color: 'var(--muted)',
              borderRadius: 6,
              padding: '4px 12px',
              fontSize: 12,
              cursor: 'pointer',
            }}
          >
            ↻ Refresh
          </button>
        </div>
      </nav>

      {/* ─────────────────────────────────────────────────────────
          Main content
      ───────────────────────────────────────────────────────── */}

      <main
        style={{
          flex: 1,
          padding: '24px',
          maxWidth: 1400,
          width: '100%',
          margin: '0 auto',
        }}
      >

        {/* Loading */}

        {loading && (
          <div
            style={{
              textAlign: 'center',
              padding: '60px 0',
              color: 'var(--muted)',
            }}
          >
            Loading threat data…
          </div>
        )}

        {/* Error */}

        {error && (
          <div
            style={{
              background: '#3d1b1b',
              border: '1px solid #f85149',
              borderRadius: 6,
              padding: '12px 16px',
              color: '#f85149',
              marginBottom: 20,
            }}
          >
            ⚠️ {error}
          </div>
        )}

        {/* ─────────────────────────────────────────────────────────
            DASHBOARD
        ───────────────────────────────────────────────────────── */}

        {!loading &&
          tab === 'dashboard' &&
          stats && (
            <>
              <h1
                style={{
                  fontSize: 18,
                  fontWeight: 700,
                  marginBottom: 20,
                  color: 'var(--text)',
                }}
              >
                Security Operations Overview
              </h1>

              {/* Clickable dashboard cards */}

              <StatsBar
                stats={stats}
                onFilterClick={openAlertFilter}
                onCorrelationClick={openCorrelations}
              />

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns:
                    '1fr 320px',
                  gap: 20,
                }}
              >

                {/* ─────────────────────────────────────────────
                    Left column
                ───────────────────────────────────────────── */}

                <div>

                  {/* Risk distribution */}

                  <div
                    style={{
                      background:
                        'var(--surface)',
                      border:
                        '1px solid var(--border)',
                      borderRadius: 8,
                      padding:
                        '16px 18px',
                      marginBottom: 20,
                    }}
                  >
                    <div
                      style={{
                        fontSize: 13,
                        fontWeight: 600,
                        marginBottom: 12,
                        color:
                          'var(--muted)',
                      }}
                    >
                      RISK DISTRIBUTION
                    </div>

                    <RiskChart
                      dist={
                        stats.risk_distribution
                      }
                      onFilterClick={
                        openAlertFilter
                      }
                    />
                  </div>

                  {/* Recent critical alerts */}

                  <div
                    style={{
                      background:
                        'var(--surface)',
                      border:
                        '1px solid var(--border)',
                      borderRadius: 8,
                      padding:
                        '16px 18px',
                    }}
                  >
                    <div
                      style={{
                        fontSize: 13,
                        fontWeight: 600,
                        marginBottom: 12,
                        color:
                          'var(--muted)',
                      }}
                    >
                      🔴 RECENT CRITICAL ALERTS
                    </div>

                    <div
                      style={{
                        display: 'flex',
                        flexDirection:
                          'column',
                        gap: 10,
                      }}
                    >
                      {stats.recent_critical
                        .length === 0 ? (
                        <p
                          style={{
                            color:
                              'var(--muted)',
                            fontSize: 12,
                          }}
                        >
                          No critical alerts
                        </p>
                      ) : (
                        stats.recent_critical.map(
                          a => (
                            <AlertCard
                              key={a.id}
                              alert={a}
                              onClick={() =>
                                setSelectedAlert(
                                  a
                                )
                              }
                              onAcknowledge={() =>
                                handleAcknowledge(
                                  a.id
                                )
                              }
                            />
                          )
                        )
                      )}
                    </div>
                  </div>
                </div>

                {/* ─────────────────────────────────────────────
                    Right column
                ───────────────────────────────────────────── */}

                <div
                  style={{
                    background:
                      'var(--surface)',
                    border:
                      '1px solid var(--border)',
                    borderRadius: 8,
                    padding:
                      '16px 18px',
                  }}
                >
                  <div
                    style={{
                      fontSize: 13,
                      fontWeight: 600,
                      marginBottom: 12,
                      color:
                        'var(--muted)',
                    }}
                  >
                    🔍 TOP THREAT INTEL
                  </div>

                  <ThreatIntelPanel
                    threats={stats.top_threats}
                  />
                </div>

              </div>
            </>
          )}

        {/* ─────────────────────────────────────────────────────────
            ALERTS
        ───────────────────────────────────────────────────────── */}

        {!loading &&
          tab === 'alerts' && (
            <>
              <div
                style={{
                  display: 'flex',
                  justifyContent:
                    'space-between',
                  alignItems: 'center',
                  marginBottom: 16,
                  gap: 16,
                  flexWrap: 'wrap',
                }}
              >
                <h1
                  style={{
                    fontSize: 18,
                    fontWeight: 700,
                    margin: 0,
                  }}
                >
                  Alert Queue{' '}
                  <span
                    style={{
                      color:
                        'var(--muted)',
                      fontWeight: 400,
                      fontSize: 14,
                    }}
                  >
                    ({filteredAlerts.length}{' '}
                    alerts)
                  </span>
                </h1>

                <div
                  style={{
                    display: 'flex',
                    gap: 6,
                    flexWrap: 'wrap',
                  }}
                >
                  {FILTERS.map(f => (
                    <button
                      key={f}
                      type="button"
                      onClick={() =>
                        setFilter(f)
                      }
                      style={{
                        background:
                          filter === f
                            ? 'var(--surface-2)'
                            : 'transparent',
                        border:
                          filter === f
                            ? '1px solid var(--accent)'
                            : '1px solid var(--border)',
                        color:
                          filter === f
                            ? 'var(--accent)'
                            : 'var(--muted)',
                        borderRadius: 6,
                        padding:
                          '4px 12px',
                        fontSize: 12,
                        cursor: 'pointer',
                      }}
                    >
                      {FILTER_LABELS[f]}
                    </button>
                  ))}
                </div>
              </div>

              <div
                style={{
                  display: 'flex',
                  flexDirection:
                    'column',
                  gap: 10,
                }}
              >
                {filteredAlerts.length ===
                0 ? (
                  <p
                    style={{
                      color:
                        'var(--muted)',
                      textAlign:
                        'center',
                      padding:
                        '40px 0',
                    }}
                  >
                    No alerts match the
                    current filter.
                  </p>
                ) : (
                  filteredAlerts.map(a => (
                    <AlertCard
                      key={a.id}
                      alert={a}
                      onClick={() =>
                        setSelectedAlert(
                          a
                        )
                      }
                      onAcknowledge={() =>
                        handleAcknowledge(
                          a.id
                        )
                      }
                    />
                  ))
                )}
              </div>
            </>
          )}

        {/* ─────────────────────────────────────────────────────────
            THREAT INTELLIGENCE
        ───────────────────────────────────────────────────────── */}

        {!loading &&
          tab === 'intel' && (
            <>
              <h1
                style={{
                  fontSize: 18,
                  fontWeight: 700,
                  marginBottom: 20,
                }}
              >
                Threat Intelligence Feed
              </h1>

              <div
                style={{
                  maxWidth: 700,
                }}
              >
                <ThreatIntelPanel
                  threats={threats}
                />
              </div>
            </>
          )}

        {/* ─────────────────────────────────────────────────────────
            CORRELATIONS
        ───────────────────────────────────────────────────────── */}

        {!loading &&
          tab === 'correlations' && (
            <>
              <div
                style={{
                  display: 'flex',
                  justifyContent:
                    'space-between',
                  alignItems: 'center',
                  marginBottom: 20,
                }}
              >
                <div>
                  <h1
                    style={{
                      fontSize: 18,
                      fontWeight: 700,
                      margin: 0,
                    }}
                  >
                    🔗 Correlated Attack Groups
                  </h1>

                  <p
                    style={{
                      color:
                        'var(--muted)',
                      fontSize: 12,
                      marginTop: 6,
                    }}
                  >
                    Related security alerts
                    grouped into potential
                    attack stories.
                  </p>
                </div>

                <button
                  type="button"
                  onClick={openDashboard}
                  style={{
                    background:
                      'transparent',
                    border:
                      '1px solid var(--border)',
                    color:
                      'var(--muted)',
                    borderRadius: 6,
                    padding:
                      '6px 12px',
                    fontSize: 12,
                    cursor: 'pointer',
                  }}
                >
                  ← Dashboard
                </button>
              </div>

              {correlationGroups.length ===
              0 ? (
                <div
                  style={{
                    background:
                      'var(--surface)',
                    border:
                      '1px solid var(--border)',
                    borderRadius: 8,
                    padding: 30,
                    textAlign:
                      'center',
                    color:
                      'var(--muted)',
                  }}
                >
                  No correlated attack
                  groups found.
                </div>
              ) : (
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns:
                      'repeat(auto-fit, minmax(280px, 1fr))',
                    gap: 16,
                  }}
                >
                  {correlationGroups.map(
                    groupId => {
                      const groupAlerts =
                        alerts.filter(
                          a =>
                            !a.is_false_positive &&
                            a.correlation_group_id ===
                              groupId
                        )

                      const criticalCount =
                        groupAlerts.filter(
                          a =>
                            a.risk_level ===
                            'CRITICAL'
                        ).length

                      const highCount =
                        groupAlerts.filter(
                          a =>
                            a.risk_level ===
                            'HIGH'
                        ).length

                      return (
                        <div
                          key={String(groupId)}
                          style={{
                            background:
                              'var(--surface)',
                            border:
                              '1px solid var(--border)',
                            borderRadius: 8,
                            padding: 18,
                          }}
                        >
                          <div
                            style={{
                              display:
                                'flex',
                              justifyContent:
                                'space-between',
                              alignItems:
                                'center',
                              marginBottom:
                                12,
                            }}
                          >
                            <span
                              style={{
                                color:
                                  '#d2a8ff',
                                fontSize:
                                  14,
                                fontWeight:
                                  700,
                              }}
                            >
                              🔗 {String(
                                groupId
                              )}
                            </span>

                            <span
                              style={{
                                fontSize:
                                  11,
                                color:
                                  'var(--muted)',
                              }}
                            >
                              {
                                groupAlerts.length
                              }{' '}
                              alerts
                            </span>
                          </div>

                          <div
                            style={{
                              display:
                                'flex',
                              gap: 8,
                              flexWrap:
                                'wrap',
                              marginBottom:
                                14,
                            }}
                          >
                            {criticalCount >
                              0 && (
                              <span
                                style={{
                                  fontSize:
                                    11,
                                  color:
                                    '#f85149',
                                  border:
                                    '1px solid #f8514966',
                                  borderRadius:
                                    4,
                                  padding:
                                    '3px 7px',
                                }}
                              >
                                🔴{' '}
                                {
                                  criticalCount
                                }{' '}
                                Critical
                              </span>
                            )}

                            {highCount >
                              0 && (
                              <span
                                style={{
                                  fontSize:
                                    11,
                                  color:
                                    '#e3a346',
                                  border:
                                    '1px solid #e3a34666',
                                  borderRadius:
                                    4,
                                  padding:
                                    '3px 7px',
                                }}
                              >
                                🟠{' '}
                                {highCount}{' '}
                                High
                              </span>
                            )}
                          </div>

                          <div
                            style={{
                              display:
                                'flex',
                              flexDirection:
                                'column',
                              gap: 8,
                            }}
                          >
                            {groupAlerts
                              .slice(
                                0,
                                3
                              )
                              .map(
                                alert => (
                                  <button
                                    key={
                                      alert.id
                                    }
                                    type="button"
                                    onClick={() =>
                                      setSelectedAlert(
                                        alert
                                      )
                                    }
                                    style={{
                                      background:
                                        'var(--surface-2)',
                                      border:
                                        '1px solid var(--border)',
                                      borderRadius:
                                        6,
                                      padding:
                                        '9px 10px',
                                      textAlign:
                                        'left',
                                      color:
                                        'var(--text)',
                                      cursor:
                                        'pointer',
                                      fontSize:
                                        11,
                                    }}
                                  >
                                    <div
                                      style={{
                                        fontWeight:
                                          600,
                                        marginBottom:
                                          4,
                                      }}
                                    >
                                      {
                                        alert.title
                                      }
                                    </div>

                                    <div
                                      style={{
                                        color:
                                          'var(--muted)',
                                      }}
                                    >
                                      {
                                        alert.risk_level
                                      }{' '}
                                      · Score{' '}
                                      {
                                        alert.risk_score
                                      }
                                    </div>
                                  </button>
                                )
                              )}
                          </div>

                          {groupAlerts.length >
                            3 && (
                            <button
                              type="button"
                              onClick={() => {
                                const first =
                                  groupAlerts[0]

                                if (first) {
                                  setSelectedAlert(
                                    first
                                  )
                                }
                              }}
                              style={{
                                marginTop: 12,
                                background:
                                  'transparent',
                                border:
                                  'none',
                                color:
                                  'var(--accent)',
                                fontSize:
                                  11,
                                cursor:
                                  'pointer',
                                padding: 0,
                              }}
                            >
                              View all related
                              alerts →
                            </button>
                          )}
                        </div>
                      )
                    }
                  )}
                </div>
              )}
            </>
          )}

      </main>

      {/* ─────────────────────────────────────────────────────────
          Alert detail slide-over
      ───────────────────────────────────────────────────────── */}

      {selectedAlert && (
        <AlertDetail
          alert={selectedAlert}
          onClose={() =>
            setSelectedAlert(null)
          }
          onAcknowledge={() =>
            handleAcknowledge(
              selectedAlert.id
            )
          }
          onFalsePositive={() =>
            handleFalsePositive(
              selectedAlert.id
            )
          }
        />
      )}

    </div>
  )
}