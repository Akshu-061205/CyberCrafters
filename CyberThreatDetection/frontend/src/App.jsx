import { useCallback, useEffect, useState } from 'react'
import './App.css'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000'
const initialTraffic = { src_ip: '192.168.1.10', dst_ip: '192.168.1.20', packets: 100, bytes: 5000, port: 443, protocol: 'TCP' }

function App() {
  const [traffic, setTraffic] = useState(initialTraffic)
  const [result, setResult] = useState(null)
  const [summary, setSummary] = useState(null)
  const [detections, setDetections] = useState([])
  const [loading, setLoading] = useState(false)
  const [refreshing, setRefreshing] = useState(true)
  const [error, setError] = useState('')

  const loadDashboard = useCallback(async () => {
    setRefreshing(true)
    try {
      const [summaryResponse, detectionsResponse] = await Promise.all([fetch(`${API_URL}/dashboard/summary`), fetch(`${API_URL}/detections?limit=8`)])
      if (!summaryResponse.ok || !detectionsResponse.ok) throw new Error()
      const [summaryData, detectionsData] = await Promise.all([summaryResponse.json(), detectionsResponse.json()])
      setSummary(summaryData); setDetections(detectionsData.detections || []); setError('')
    } catch { setError(`Cannot reach the threat API at ${API_URL}. Start the backend and try again.`) } finally { setRefreshing(false) }
  }, [])

  useEffect(() => { loadDashboard() }, [loadDashboard])
  const updateField = ({ target: { name, value } }) => setTraffic((current) => ({ ...current, [name]: ['packets', 'bytes', 'port'].includes(name) ? Number(value) : value }))
  const submitTraffic = async (event) => {
    event.preventDefault(); setLoading(true); setError('')
    try {
      const response = await fetch(`${API_URL}/predict`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(traffic) })
      const data = await response.json()
      if (!response.ok) throw new Error(data.details?.join(' ') || data.error || 'Prediction failed.')
      setResult(data); await loadDashboard()
    } catch (requestError) { setError(requestError.message || 'Prediction failed.') } finally { setLoading(false) }
  }

  return <main className="app-shell">
    <header className="topbar"><a className="brand" href="#top"><span className="brand-mark">◈</span> Cyber<span>Sentinel</span></a><div className="api-state"><span className={`status-dot ${error ? 'offline' : 'online'}`} /> {error ? 'API offline' : 'Model API connected'}</div></header>
    <section className="hero" id="top"><div><p className="eyebrow">NETWORK THREAT DETECTION</p><h1>Spot threats before they spread.</h1><p className="hero-copy">Submit traffic metadata to the trained classifier and get an immediate, explainable risk assessment.</p></div><div className="model-badge"><span>◉</span><div><small>ACTIVE MODEL</small><strong>Gaussian Naive Bayes · v1.0.0</strong></div></div></section>
    {error && <div className="notice"><span>!</span><div>{error}<button onClick={loadDashboard}>Retry connection</button></div></div>}
    <section className="metrics" aria-label="Threat overview"><Metric label="Traffic analyzed" value={summary?.total_analyzed ?? '—'} icon="◎" /><Metric label="Average risk" value={summary ? `${summary.average_risk_score}%` : '—'} icon="◌" /><Metric label="Suspicious" value={summary?.detections?.Suspicious ?? '—'} icon="△" tone="amber" /><Metric label="Malicious" value={summary?.detections?.Malicious ?? '—'} icon="✦" tone="red" /></section>
    <section className="workspace"><form className="panel traffic-form" onSubmit={submitTraffic}><div className="panel-heading"><div><p className="eyebrow">INPUT</p><h2>Analyze network traffic</h2></div><span className="chip">LIVE</span></div><div className="form-grid"><Field label="Source IP" name="src_ip" value={traffic.src_ip} onChange={updateField} placeholder="192.168.1.10" /><Field label="Destination IP" name="dst_ip" value={traffic.dst_ip} onChange={updateField} placeholder="192.168.1.20" /><Field label="Packets" name="packets" type="number" min="0" value={traffic.packets} onChange={updateField} /><Field label="Bytes" name="bytes" type="number" min="0" value={traffic.bytes} onChange={updateField} /><Field label="Port" name="port" type="number" min="1" max="65535" value={traffic.port} onChange={updateField} /><label className="field"><span>Protocol</span><select name="protocol" value={traffic.protocol} onChange={updateField}><option>TCP</option><option>UDP</option><option>ICMP</option></select></label></div><button className="primary-button" disabled={loading}>{loading ? 'Analyzing traffic…' : 'Run threat analysis'} <span>→</span></button></form>
      <section className="panel result-panel"><div className="panel-heading"><div><p className="eyebrow">MODEL OUTPUT</p><h2>Risk assessment</h2></div>{result && <span className={`severity ${result.severity}`}>{result.severity} risk</span>}</div>{result ? <Result result={result} /> : <div className="empty-result"><span>◌</span><p>Run an analysis to see the model decision, confidence, and contributing traffic signals.</p></div>}</section></section>
    <section className="panel detections-panel"><div className="panel-heading"><div><p className="eyebrow">ACTIVITY</p><h2>Recent detections</h2></div><button className="text-button" onClick={loadDashboard} disabled={refreshing}>{refreshing ? 'Refreshing…' : 'Refresh'}</button></div><div className="table-wrap"><table><thead><tr><th>Time</th><th>Source → destination</th><th>Protocol</th><th>Prediction</th><th>Risk</th></tr></thead><tbody>{detections.length ? detections.map((item) => <tr key={item.id}><td>{new Date(item.analyzed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</td><td className="mono">{item.traffic.src_ip} <span>→</span> {item.traffic.dst_ip}</td><td>{item.traffic.protocol || '—'} / {item.traffic.port || '—'}</td><td><span className={`prediction ${item.prediction.toLowerCase()}`}>{item.prediction}</span></td><td><strong>{item.risk_score}</strong><span className="risk-track"><i style={{ width: `${item.risk_score}%` }} /></span></td></tr>) : <tr><td colSpan="5" className="no-data">No analyses yet. Submit traffic above to begin.</td></tr>}</tbody></table></div></section>
  </main>
}

function Field({ label, ...props }) { return <label className="field"><span>{label}</span><input required {...props} /></label> }
function Metric({ label, value, icon, tone = '' }) { return <article className={`metric ${tone}`}><span className="metric-icon">{icon}</span><div><small>{label}</small><strong>{value}</strong></div></article> }
function Result({ result }) { return <div className="result-content"><div className="result-score"><div className={`score-ring ${result.severity}`} style={{ '--score': `${result.risk_score * 3.6}deg` }}><div><strong>{result.risk_score}</strong><span>/ 100</span></div></div><div><p className="result-label">Classification</p><h3>{result.prediction}</h3><p className="confidence">{Math.round((result.model?.confidence || 0) * 100)}% model confidence</p></div></div><div className="reasons"><p className="result-label">Observed signals</p>{result.reasons.map((reason) => <span key={reason}>✓ {reason}</span>)}</div><div className="probabilities"><p className="result-label">Class probabilities</p>{Object.entries(result.model?.probabilities || {}).map(([label, probability]) => <div className="probability" key={label}><span>{label}</span><div><i style={{ width: `${probability * 100}%` }} /></div><b>{Math.round(probability * 100)}%</b></div>)}</div></div> }

export default App
