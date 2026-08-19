import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import {
  ApiOutlined,
  ApartmentOutlined,
  BookOutlined,
  BugOutlined,
  CodeOutlined,
  CopyOutlined,
  DatabaseOutlined,
  DashboardOutlined,
  ArrowDownOutlined,
  ArrowUpOutlined,
  FileAddOutlined,
  FileTextOutlined,
  Html5Outlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  SafetyCertificateOutlined,
  SaveOutlined,
  ToolOutlined,
  TrophyOutlined,
  UploadOutlined,
} from '@ant-design/icons'
import {
  Alert,
  Breadcrumb,
  Button,
  Card,
  Collapse,
  ConfigProvider,
  Descriptions,
  Divider,
  Empty,
  Form,
  Input,
  InputNumber,
  Layout,
  Menu,
  Pagination,
  Popconfirm,
  Progress,
  Select,
  Space,
  Spin,
  Statistic,
  Table,
  Tabs,
  Tag,
  Typography,
  Upload,
  message,
} from 'antd'
import type { MenuProps, TabsProps } from 'antd'
import { api } from './api'
import './styles.css'

const { Header, Sider, Content } = Layout
const { Text, Title, Paragraph } = Typography

type VulnerabilityKey = 'command-injection' | 'file-upload' | 'sql-injection' | 'log4j' | 'xss' | 'tencent-waf'
type DirectWafTarget = { label: string; description: string }
type WafSceneDetail = { configured: boolean; base_url?: string; security?: string; error?: string }
type TencentWafState = { configured: boolean; ip?: string; host?: string; preflight_status?: number; preflight_result?: string; error?: string }
type CandidateStatus = 'pending_test' | 'test_success' | 'test_failed' | 'rejected' | 'archived'
type ArchiveOutcome = 'bypass_success' | 'bypass_failure'
type WorkspaceKey = 'dashboard' | 'library' | 'agent' | 'encoding' | 'cross' | 'waf' | 'samples' | 'reports' | 'curl-tool'

type WafTestResult = 'waf_blocked' | 'waf_bypassed' | 'application_response' | 'execution_confirmed' | 'inconclusive' | 'request_error'
type WafTestRun = {
  id: string; agent: 'semantic' | 'encoding' | 'cross'; candidate_id: string; base_name: string
  vulnerability: VulnerabilityKey; payload_snapshot: string; status: 'queued' | 'running' | 'completed' | 'failed'
  result: WafTestResult | null; evidence: string | null; request_summary: string | null; response_excerpt: string | null
  http_status: number | null; error_message: string | null; created_at: string; started_at: string | null; completed_at: string | null
}
type WafScene = { configured: boolean; base_url?: string; security?: string; supported: VulnerabilityKey[]; direct_targets?: Record<string, DirectWafTarget>; dvwa?: WafSceneDetail; tencent_waf?: TencentWafState; error?: string }

type Payload = {
  id: string
  name: string
  vulnerability: VulnerabilityKey
  category: string
  delivery: string
  target: string
  difficulty: string
  content: string
  usage_method: string
  success_indicators: string
  created_at: string
  archive_outcome: ArchiveOutcome | null
  latest_waf_test?: WafTestRun | null
  used_direction_ids?: string[]
  next_directions?: IterationDirection[]
}

type IterationDirection = { id: string; label: string; reason: string }
type SemanticPart = { part_id: string; part_type: string; raw: string; required: boolean; semantic_role: string; dependencies: string[]; confidence: number }
type SemanticPartOperation = { operation: 'replace' | 'add' | 'remove'; part_id: string; part_type: string; value?: string; reason?: string }

type Candidate = {
  id: string
  task_id: string
  base_payload_id: string
  base_payload_name: string
  base_vulnerability: VulnerabilityKey
  base_target: string
  base_difficulty: string
  content: string
  delivery: string
  rule_labels: string[]
  explanation: string
  confidence: number
  status: CandidateStatus
  test_note: string | null
  created_at: string
  latest_waf_test?: WafTestRun | null
  used_direction_ids: string[]
  next_directions: IterationDirection[]
  base_parts?: SemanticPart[]
  candidate_parts?: SemanticPart[]
  part_operations?: SemanticPartOperation[]
  parser_confidence?: number
  parser_status?: string
  unsupported_reason?: string | null
  semantic_delta?: { changed_parts?: string[]; added_parts?: string[]; removed_parts?: string[]; summary?: string; target_preserved?: boolean; context_preserved?: boolean }
  verification_spec?: Record<string, unknown> | null
}

type IterationTask = {
  id: string
  status: 'queued' | 'running' | 'completed' | 'failed'
  candidate_count: number
  error_message?: string | null
  candidates: Candidate[]
}

type EncodingStep = {
  type: string
  mode: 'full' | 'special' | 'command_name' | 'legacy_unverified'
}

type EncodingCandidate = {
  id: string
  task_id: string
  base_payload_id: string
  base_payload_name: string
  base_vulnerability: VulnerabilityKey
  base_target: string
  base_difficulty: string
  content: string
  delivery: string
  encoding_chain: EncodingStep[]
  decode_path: string[]
  rule_labels: string[]
  explanation: string
  confidence: number
  status: CandidateStatus
  test_note: string | null
  origin?: 'generated' | 'semantic_boundary_migration'
  migration_note?: string | null
  created_at: string
  latest_waf_test?: WafTestRun | null
  used_direction_ids: string[]
  next_directions: IterationDirection[]
}

type EncodingTask = {
  id: string
  status: 'queued' | 'running' | 'completed' | 'failed'
  candidate_count: number
  error_message?: string | null
  candidates: EncodingCandidate[]
}

type CrossSource = {
  id: string
  archived_payload_id: string
  semantic_candidate_id: string
  name: string
  vulnerability: VulnerabilityKey
  category: string
  delivery: string
  target: string
  difficulty: string
  content: string
  rule_labels: string[]
  available_chain_count: number
  created_at: string
}

type CrossCandidate = {
  id: string
  task_id: string
  cross_source_id: string
  source_name: string
  source_vulnerability: VulnerabilityKey
  source_target: string
  source_difficulty: string
  source_delivery: string
  semantic_content: string
  semantic_rule_labels: string[]
  content: string
  encoding_chain: EncodingStep[]
  decode_path: string[]
  rule_labels: string[]
  status: CandidateStatus
  test_note: string | null
  created_at: string
  latest_waf_test?: WafTestRun | null
}

type CrossTask = {
  id: string
  status: 'completed' | 'failed'
  candidate_count: number
  error_message?: string | null
  candidates: CrossCandidate[]
}

type SuccessSample = {
  id: string
  agent: 'semantic' | 'encoding' | 'cross'
  candidate_id: string
  archived_payload_id: string | null
  name: string
  vulnerability: VulnerabilityKey
  category: string
  delivery: string
  target: string
  difficulty: string
  content: string
  test_note: string | null
  provenance: Record<string, unknown>
  created_at: string
  updated_at: string
}

type ReportImage = {
  id: string
  report_id: string
  original_name: string
  relative_path: string
  media_type: string
  size_bytes: number
  caption: string
  sort_order: number
  content_url: string
  created_at: string
  updated_at: string
}

type Report = {
  id: string
  success_sample_id: string
  source_agent: SuccessSample['agent']
  source_candidate_id: string
  source_archived_payload_id: string | null
  sample_name: string
  vulnerability: VulnerabilityKey
  category: string
  delivery: string
  target: string
  payload_content: string
  sample_test_note: string | null
  provenance: Record<string, unknown>
  sample_created_at: string
  title: string
  verification_environment: string
  prerequisites: string
  verification_steps: string
  actual_result: string
  conclusion: string
  tester: string
  verification_date: string
  notes: string
  source_status: string
  images: ReportImage[]
  created_at: string
  updated_at: string
}

type ReportEditableField = 'payload_content' | 'title' | 'verification_environment' | 'prerequisites' | 'verification_steps' | 'actual_result' | 'conclusion' | 'tester' | 'verification_date' | 'notes'
type ReportSaveState = 'saved' | 'dirty' | 'saving' | 'error'
type PageResult<T> = { items: T[]; total: number; next_cursor: number | null }
type DashboardSummary = {
  payload_count: number
  success_sample_count: number
  semantic_pool_pending: number
  encoding_pool_pending: number
  pending: number
  success: number
  failed: number
  completed: number
  rate: number | null
  agents: Record<'semantic' | 'encoding' | 'cross', { pending: number; success: number; failed: number; completed: number; rate: number | null }>
}

const PAGE_SIZE = 50

type IterationPoolItem = {
  id: string
  agent: 'semantic' | 'encoding'
  source_payload_id: string
  snapshot_payload_id: string
  status: 'pending' | 'started'
  task_id: string | null
  task_status: 'queued' | 'running' | 'completed' | 'failed' | 'unknown' | null
  task_error: string | null
  created_at: string
  started_at: string | null
  snapshot: Omit<Payload, 'created_at' | 'usage_method' | 'success_indicators'>
}

type AgentDocument = {
  id: string
  kind: 'skill' | 'prompt'
  title: string
  content: string
}

const vulnerabilityDefinitions: Record<VulnerabilityKey, { label: string; tagColor: string; icon: ReactNode; types: string[] }> = {
  'command-injection': { label: '命令注入', tagColor: 'volcano', icon: <CodeOutlined />, types: ['基础命令', '参数拼接', '编码变体'] },
  'file-upload': { label: '文件上传', tagColor: 'gold', icon: <UploadOutlined />, types: ['文件名校验', '内容校验', '路径处理'] },
  'sql-injection': { label: 'SQL 注入', tagColor: 'red', icon: <DatabaseOutlined />, types: ['通用语法', '布尔判定', '报错分析'] },
  log4j: { label: 'Log4j', tagColor: 'purple', icon: <BugOutlined />, types: ['环境确认', '日志触发', '编码变体'] },
  xss: { label: 'XSS', tagColor: 'cyan', icon: <Html5Outlined />, types: ['反射型', '存储型', 'DOM 型'] },
  'tencent-waf': { label: '腾讯云 WAF', tagColor: 'orange', icon: <SafetyCertificateOutlined />, types: ['XSS', 'SQL注入', '命令注入', '路径遍历', '模板注入', 'XXE', '代码执行', 'SSRF', '文件包含', '反序列化', 'WebShell', '敏感文件', '扫描探测'] },
}

const vulnerabilityKeys = Object.keys(vulnerabilityDefinitions) as VulnerabilityKey[]
const deliveryOptions = ['URL 查询参数', '表单字段', 'JSON 请求体', 'multipart/form-data 文件字段', '请求头 / Cookie']
const targetDifficulties: Record<string, string[]> = {
  DVWA: ['Low', 'Medium', 'High', 'Impossible'],
  Pikachu: ['基础', '进阶', '高级'],
  Solr: ['Low', 'Medium', 'High'],
  通用: ['自定义'],
}

const encodingTypeLabels: Record<string, string> = {
  url_percent: 'URL 百分号',
  html_entity_decimal: 'HTML 十进制实体',
  html_entity_hex: 'HTML 十六进制实体',
  unicode_escape: 'Unicode 转义',
  json_unicode_escape: 'JSON Unicode 转义',
  hex_text: '十六进制文本',
  base64: 'Base64',
  base64url: 'Base64URL',
  shell_printf_octal_command: 'Shell printf 八进制命令构造',
  shell_ansi_c_octal_command: 'Shell ANSI-C 八进制命令构造',
  legacy_semantic_boundary_migration: '历史语义边界迁移',
}

function encodingModeLabel(mode: EncodingStep['mode']) {
  if (mode === 'full') return '全量'
  if (mode === 'special') return '特殊字符'
  if (mode === 'command_name') return '直接命令名'
  if (mode === 'legacy_unverified') return '待新版重放复核'
  return mode
}

function encodingPrerequisites(chain: EncodingStep[]) {
  if (chain.some((step) => step.type === 'shell_printf_octal_command')) return '解释前提：目标 Shell 支持命令替换与 printf（通常为 Bash）。'
  if (chain.some((step) => step.type === 'shell_ansi_c_octal_command')) return "解释前提：目标 Shell 支持 Bash ANSI-C $'...' 八进制转义语法。"
  return ''
}

const sampleAgentLabels: Record<SuccessSample['agent'], string> = {
  semantic: '语义迭代',
  encoding: '编码迭代',
  cross: '正向交叉',
}

function deliveryFor(vulnerability: VulnerabilityKey) {
  if (vulnerability === 'file-upload') return 'multipart/form-data 文件字段'
  if (vulnerability === 'sql-injection') return 'URL 查询参数'
  if (vulnerability === 'tencent-waf') return 'URL路径'
  return '表单字段'
}

function statusTag(status: CandidateStatus) {
  const config: Record<CandidateStatus, [string, string]> = {
    pending_test: ['blue', '待测试'],
    test_success: ['green', '测试成功'],
    test_failed: ['red', '测试失败'],
    rejected: ['default', '已拒绝'],
    archived: ['purple', '已归档'],
  }
  const [color, label] = config[status]
  return <Tag color={color}>{label}</Tag>
}

function archiveOutcomeTag(outcome: ArchiveOutcome | null) {
  if (!outcome) return null
  return outcome === 'bypass_success'
    ? <Tag color="green">绕过成功</Tag>
    : <Tag color="red">绕过失败</Tag>
}

function retryablePoolItems(items: IterationPoolItem[]) {
  return items.filter((item) => item.status === 'pending')
}

function reportUpdatePayload(report: Report) {
  return {
    payload_content: report.payload_content,
    title: report.title,
    verification_environment: report.verification_environment,
    prerequisites: report.prerequisites,
    verification_steps: report.verification_steps,
    actual_result: report.actual_result,
    conclusion: report.conclusion,
    tester: report.tester,
    verification_date: report.verification_date,
    notes: report.notes,
  }
}

export function App() {
  const [messageApi, messageContext] = message.useMessage()
  const [collapsed, setCollapsed] = useState(false)
  const [workspace, setWorkspace] = useState<WorkspaceKey>('dashboard')
  const [libraryTab, setLibraryTab] = useState('source')
  const [agentTab, setAgentTab] = useState('workspace')
  const [encodingAgentTab, setEncodingAgentTab] = useState('workspace')
  const [payloads, setPayloads] = useState<Payload[]>([])
  const [candidates, setCandidates] = useState<Candidate[]>([])
  const [encodingCandidates, setEncodingCandidates] = useState<EncodingCandidate[]>([])
  const [crossSources, setCrossSources] = useState<CrossSource[]>([])
  const [crossCandidates, setCrossCandidates] = useState<CrossCandidate[]>([])
  const [successSamples, setSuccessSamples] = useState<SuccessSample[]>([])
  const [reports, setReports] = useState<Report[]>([])
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummary | null>(null)
  const [page, setPage] = useState({ payloads: 1, candidates: 1, encodingCandidates: 1, crossSources: 1, crossCandidates: 1, samples: 1, reports: 1 })
  const [totals, setTotals] = useState({ payloads: 0, candidates: 0, encodingCandidates: 0, crossSources: 0, crossCandidates: 0, samples: 0, reports: 0 })
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null)
  const [reportDraft, setReportDraft] = useState<Report | null>(null)
  const [reportTab, setReportTab] = useState('edit')
  const [reportSaveState, setReportSaveState] = useState<ReportSaveState>('saved')
  const [reportUploading, setReportUploading] = useState(false)
  const reportAutoSaveTimer = useRef<number | null>(null)
  const reportSaveRevision = useRef(0)
  const dataLoadRevision = useRef(0)
  const dataLoadPromise = useRef<Promise<void> | null>(null)
  const dataLoadingRequested = useRef(false)
  const liveWafPromise = useRef<Promise<void> | null>(null)
  const semanticPollPromise = useRef<Promise<void> | null>(null)
  const encodingPollPromise = useRef<Promise<void> | null>(null)
  const wafScenePromise = useRef<Promise<void> | null>(null)
  const wafRunsPromise = useRef<Promise<void> | null>(null)
  const [semanticPool, setSemanticPool] = useState<IterationPoolItem[]>([])
  const [encodingPool, setEncodingPool] = useState<IterationPoolItem[]>([])
  const [wafScene, setWafScene] = useState<WafScene | null>(null)
  const [wafRuns, setWafRuns] = useState<WafTestRun[]>([])
  const [wafLoading, setWafLoading] = useState(false)
  const [loading, setLoading] = useState(true)
  const [apiError, setApiError] = useState('')
  const [editingId, setEditingId] = useState<string | null>(null)
  const [expandedCard, setExpandedCard] = useState<string | null>(null)
  const [expandedCandidate, setExpandedCandidate] = useState<string | null>(null)
  const [expandedEncodingCandidate, setExpandedEncodingCandidate] = useState<string | null>(null)
  const [expandedCrossCandidate, setExpandedCrossCandidate] = useState<string | null>(null)
  const [expandedSample, setExpandedSample] = useState<string | null>(null)
  const [editDraft, setEditDraft] = useState<{
    name: string
    content: string
    delivery: string
    usage_method: string
    success_indicators: string
  } | null>(null)
  const [selectedBaseId, setSelectedBaseId] = useState<string | undefined>()
  const [selectedEncodingBaseId, setSelectedEncodingBaseId] = useState<string | undefined>()
  const [selectedCrossSourceId, setSelectedCrossSourceId] = useState<string | undefined>()
  const [candidateCount, setCandidateCount] = useState(5)
  const [encodingCandidateCount, setEncodingCandidateCount] = useState(5)
  const [crossCandidateCount, setCrossCandidateCount] = useState(5)
  const [activeTask, setActiveTask] = useState<IterationTask | null>(null)
  const [activeEncodingTask, setActiveEncodingTask] = useState<EncodingTask | null>(null)
  const [activeCrossTask, setActiveCrossTask] = useState<CrossTask | null>(null)
  const [generating, setGenerating] = useState(false)
  const [encodingGenerating, setEncodingGenerating] = useState(false)
  const [crossGenerating, setCrossGenerating] = useState(false)
  const [archivingCandidateKey, setArchivingCandidateKey] = useState<string | null>(null)
  const [testNotes, setTestNotes] = useState<Record<string, string>>({})
  const [encodingTestNotes, setEncodingTestNotes] = useState<Record<string, string>>({})
  const [crossTestNotes, setCrossTestNotes] = useState<Record<string, string>>({})
  const [sampleAgentFilter, setSampleAgentFilter] = useState<string | undefined>()
  const [sampleVulnerabilityFilter, setSampleVulnerabilityFilter] = useState<string | undefined>()
  const [sampleTargetFilter, setSampleTargetFilter] = useState<string | undefined>()
  const [sampleDeliveryFilter, setSampleDeliveryFilter] = useState<string | undefined>()
  const [agentDocuments, setAgentDocuments] = useState<AgentDocument[]>([])
  const [agentDocumentsLoading, setAgentDocumentsLoading] = useState(false)
  const [agentDocumentsError, setAgentDocumentsError] = useState('')
  const [selectedDocumentId, setSelectedDocumentId] = useState('skill/vulnerability-semantic-understanding')
  const [encodingDocuments, setEncodingDocuments] = useState<AgentDocument[]>([])
  const [encodingDocumentsLoading, setEncodingDocumentsLoading] = useState(false)
  const [encodingDocumentsError, setEncodingDocumentsError] = useState('')
  const [selectedEncodingDocumentId, setSelectedEncodingDocumentId] = useState('skill/encoding-context-understanding')
  const [draft, setDraft] = useState({
    vulnerability: 'command-injection' as VulnerabilityKey,
    category: '基础命令',
    delivery: '表单字段',
    target: '通用',
    name: '',
    content: '',
    usage_method: '',
    success_indicators: '',
  })

  const selectedBase = payloads.find((payload) => payload.id === selectedBaseId)
  const selectedEncodingBase = payloads.find((payload) => payload.id === selectedEncodingBaseId)
  const selectedCrossSource = crossSources.find((source) => source.id === selectedCrossSourceId)

  const refreshPayloadResource = async () => {
    const cursor = (page.payloads - 1) * PAGE_SIZE
    const result = await api<PageResult<Payload>>(`/payloads?limit=${PAGE_SIZE}&cursor=${cursor}`)
    setPayloads(result.items)
    setTotals((current) => ({ ...current, payloads: result.total }))
  }

  const mergeArchivedPayload = (archived: Payload) => {
    setPayloads((current) => [archived, ...current.filter((item) => item.id !== archived.id)].slice(0, PAGE_SIZE))
    setTotals((current) => ({ ...current, payloads: current.payloads + 1 }))
    void refreshPayloadResource().catch(() => {
      messageApi.warning('归档成功，但 Payload 列表刷新延迟')
    })
  }

  const loadData = (showLoading = false) => {
    if (showLoading) {
      dataLoadingRequested.current = true
      setLoading(true)
    }
    const revision = ++dataLoadRevision.current
    let failed = false
    const reportLoadError = (error: unknown) => {
      failed = true
      if (revision === dataLoadRevision.current) setApiError(error instanceof Error ? error.message : '无法连接本地 API')
    }
    const finishInitialLoading = () => {
      if (revision === dataLoadRevision.current && dataLoadingRequested.current) {
        dataLoadingRequested.current = false
        setLoading(false)
      }
    }
    const offset = (value: number) => (value - 1) * PAGE_SIZE
    const loadPage = <T,>(path: string) => api<PageResult<T>>(`${path}${path.includes('?') ? '&' : '?'}limit=${PAGE_SIZE}&cursor=${offset(pageForPath(path))}`)
    const pageForPath = (path: string) => {
      if (path.startsWith('/payloads')) return page.payloads
      if (path.startsWith('/candidates')) return page.candidates
      if (path.startsWith('/encoding-candidates')) return page.encodingCandidates
      if (path.startsWith('/cross-sources')) return page.crossSources
      if (path.startsWith('/cross-candidates')) return page.crossCandidates
      if (path.startsWith('/success-samples')) return page.samples
      return page.reports
    }
    const applyPage = <T,>(key: keyof typeof totals, result: PageResult<T>, setter: (items: T[]) => void) => {
      if (revision !== dataLoadRevision.current) return
      setter(result.items)
      setTotals((current) => ({ ...current, [key]: result.total }))
    }
    let request: Promise<void>
    if (workspace === 'dashboard') {
      request = api<DashboardSummary>('/dashboard-summary').then((summary) => {
        if (revision === dataLoadRevision.current) setDashboardSummary(summary)
      })
    } else if (workspace === 'library') {
      request = loadPage<Payload>('/payloads').then((result) => applyPage('payloads', result, setPayloads))
    } else if (workspace === 'agent') {
      request = Promise.all([
        loadPage<Payload>('/payloads'),
        loadPage<Candidate>('/candidates'),
        api<IterationPoolItem[]>('/iteration-pools/semantic'),
      ]).then(([nextPayloads, nextCandidates, nextPool]) => {
        applyPage('payloads', nextPayloads, setPayloads)
        applyPage('candidates', nextCandidates, setCandidates)
        if (revision === dataLoadRevision.current) setSemanticPool(nextPool)
      })
    } else if (workspace === 'encoding') {
      request = Promise.all([
        loadPage<Payload>('/payloads'),
        loadPage<EncodingCandidate>('/encoding-candidates'),
        api<IterationPoolItem[]>('/iteration-pools/encoding'),
      ]).then(([nextPayloads, nextCandidates, nextPool]) => {
        applyPage('payloads', nextPayloads, setPayloads)
        applyPage('encodingCandidates', nextCandidates, setEncodingCandidates)
        if (revision === dataLoadRevision.current) setEncodingPool(nextPool)
      })
    } else if (workspace === 'cross') {
      request = Promise.all([
        loadPage<CrossSource>('/cross-sources'),
        loadPage<CrossCandidate>('/cross-candidates'),
      ]).then(([nextSources, nextCandidates]) => {
        applyPage('crossSources', nextSources, setCrossSources)
        applyPage('crossCandidates', nextCandidates, setCrossCandidates)
      })
    } else if (workspace === 'samples') {
      const filters = new URLSearchParams()
      if (sampleAgentFilter) filters.set('agent', sampleAgentFilter)
      if (sampleVulnerabilityFilter) filters.set('vulnerability', sampleVulnerabilityFilter)
      if (sampleTargetFilter) filters.set('target', sampleTargetFilter)
      if (sampleDeliveryFilter) filters.set('delivery', sampleDeliveryFilter)
      request = Promise.all([
        loadPage<SuccessSample>(`/success-samples?${filters.toString()}`),
        loadPage<Report>('/reports'),
      ]).then(([nextSamples, nextReports]) => {
        applyPage('samples', nextSamples, setSuccessSamples)
        applyPage('reports', nextReports, setReports)
      })
    } else if (workspace === 'reports') {
      request = loadPage<Report>('/reports').then((nextReports) => {
        applyPage('reports', nextReports, setReports)
        if (revision !== dataLoadRevision.current) return
        setSelectedReportId((current) => current && nextReports.items.some((report) => report.id === current) ? current : nextReports.items[0]?.id || null)
        setReportDraft((current) => current && nextReports.items.some((report) => report.id === current.id) ? current : nextReports.items[0] || null)
      })
    } else {
      request = Promise.resolve()
    }
    request = request.catch(reportLoadError).then(() => {
      if (!failed && revision === dataLoadRevision.current) setApiError('')
    }).finally(() => {
      if (dataLoadPromise.current === request) dataLoadPromise.current = null
      finishInitialLoading()
    })
    dataLoadPromise.current = request
    return request
  }

  const refreshActiveWafRuns = () => {
    if (dataLoadPromise.current) return dataLoadPromise.current
    if (liveWafPromise.current) return liveWafPromise.current
    const activeRuns = [...candidates, ...encodingCandidates, ...crossCandidates]
      .map((candidate) => candidate.latest_waf_test)
      .filter((run): run is WafTestRun => Boolean(run && ['queued', 'running'].includes(run.status)))
    const runIds = [...new Set(activeRuns.map((run) => run.id))]
    if (runIds.length === 0) return Promise.resolve()
    const request = Promise.all(runIds.map((runId) => api<WafTestRun>(`/waf-test-runs/${runId}`))).then((runs) => {
      const byId = new Map(runs.map((run) => [run.id, run]))
      setCandidates((current) => current.map((candidate) => {
        const updated = candidate.latest_waf_test && byId.get(candidate.latest_waf_test.id)
        return updated ? { ...candidate, latest_waf_test: updated } : candidate
      }))
      setEncodingCandidates((current) => current.map((candidate) => {
        const updated = candidate.latest_waf_test && byId.get(candidate.latest_waf_test.id)
        return updated ? { ...candidate, latest_waf_test: updated } : candidate
      }))
      setCrossCandidates((current) => current.map((candidate) => {
        const updated = candidate.latest_waf_test && byId.get(candidate.latest_waf_test.id)
        return updated ? { ...candidate, latest_waf_test: updated } : candidate
      }))
      setWafRuns((current) => current.map((run) => byId.get(run.id) || run))
    }).catch(() => undefined).finally(() => {
      if (liveWafPromise.current === request) liveWafPromise.current = null
    })
    liveWafPromise.current = request
    return request
  }

  const loadWafScene = () => {
    if (wafScenePromise.current) return wafScenePromise.current
    const request = api<WafScene>('/waf-test-scene')
      .then(setWafScene)
      .catch((error) => { messageApi.error(error instanceof Error ? error.message : '无法读取 WAF 测试场') })
      .finally(() => {
        if (wafScenePromise.current === request) wafScenePromise.current = null
      })
    wafScenePromise.current = request
    return request
  }

  const loadWafRuns = () => {
    if (wafRunsPromise.current) return wafRunsPromise.current
    const request = api<WafTestRun[]>('/waf-test-runs')
      .then(setWafRuns)
      .catch(() => undefined)
      .finally(() => {
        if (wafRunsPromise.current === request) wafRunsPromise.current = null
      })
    wafRunsPromise.current = request
    return request
  }

  const loadWafData = () => Promise.all([loadWafScene(), loadWafRuns()]).then(() => undefined)

  const preflightWaf = async () => {
    setWafLoading(true)
    try { await api<WafScene>('/waf-test-scene/preflight', { method: 'POST' }); await loadWafData(); messageApi.success('DVWA + 雷池预检通过') }
    catch (error) { messageApi.error(error instanceof Error ? error.message : 'WAF 预检失败') }
    finally { setWafLoading(false) }
  }

  const sendToWaf = async (agent: 'semantic' | 'encoding' | 'cross', candidateId: string) => {
    try {
      // 根据agent类型查找对应的候选
      let candidate: any = null
      let content = ''
      let baseName = ''

      if (agent === 'semantic') {
        candidate = candidates.find(c => c.id === candidateId)
        if (candidate) {
          content = candidate.content
          baseName = candidate.base_payload_name
        }
      } else if (agent === 'encoding') {
        candidate = encodingCandidates.find(c => c.id === candidateId)
        if (candidate) {
          content = candidate.content
          baseName = candidate.base_payload_name
        }
      } else if (agent === 'cross') {
        candidate = crossCandidates.find(c => c.id === candidateId)
        if (candidate) {
          content = candidate.content
          baseName = candidate.source_name
        }
      }

      if (!candidate) {
        messageApi.error('未找到候选信息')
        return
      }

      const scene = wafScene || await api<WafScene>('/waf-test-scene')
      if (!wafScene) setWafScene(scene)
      const useTencentWaf = Boolean(
        scene.tencent_waf?.configured && scene.direct_targets?.['tencent-waf']
      )

      // 候选测试优先进入当前可用的腾讯云 WAF，避免通用样例落到失联的 DVWA。
      if (useTencentWaf) {
        await api<WafTestRun>('/waf-test-runs/direct', {
          method: 'POST',
          body: JSON.stringify({
            target: 'tencent-waf',
            content,
            name: baseName,
            agent,
            candidate_id: candidateId,
            vulnerability: candidate.base_vulnerability || candidate.source_vulnerability
          })
        })
      } else {
        await api<WafTestRun>('/waf-test-runs', {
          method: 'POST',
          body: JSON.stringify({ agent, candidate_id: candidateId })
        })
      }

      await loadData()
      await loadWafData()
      messageApi.success(`候选已进入${useTencentWaf ? '腾讯云 ' : ''}WAF 测试队列`)
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '创建 WAF 测试失败')
    }
  }

  const loadAgentDocuments = async () => {
    setAgentDocumentsLoading(true)
    try {
      const documents = await api<AgentDocument[]>('/semantic-agent/documents')
      setAgentDocuments(documents)
      setSelectedDocumentId((current) => documents.some((document) => document.id === current) ? current : documents[0]?.id || '')
      setAgentDocumentsError('')
    } catch (error) {
      const detail = error instanceof Error ? error.message : '无法读取 Agent 文档'
      setAgentDocumentsError(detail === 'Not Found' ? '本地后端尚未加载文档接口，请重启 FastAPI 服务（127.0.0.1:8000）后重试。' : detail)
    } finally {
      setAgentDocumentsLoading(false)
    }
  }

  const loadEncodingDocuments = async () => {
    setEncodingDocumentsLoading(true)
    try {
      const documents = await api<AgentDocument[]>('/encoding-agent/documents')
      setEncodingDocuments(documents)
      setSelectedEncodingDocumentId((current) => documents.some((document) => document.id === current) ? current : documents[0]?.id || '')
      setEncodingDocumentsError('')
    } catch (error) {
      const detail = error instanceof Error ? error.message : '无法读取编码 Agent 文档'
      setEncodingDocumentsError(detail === 'Not Found' ? '本地后端尚未加载编码 Agent 文档接口，请重启 FastAPI 服务后重试。' : detail)
    } finally {
      setEncodingDocumentsLoading(false)
    }
  }

  useEffect(() => {
    void loadData(workspace === 'dashboard')
  }, [workspace, page, sampleAgentFilter, sampleVulnerabilityFilter, sampleTargetFilter, sampleDeliveryFilter])

  useEffect(() => {
    if (workspace === 'waf') void loadWafData()
    else if (workspace === 'curl-tool') void loadWafScene()
  }, [workspace])

  useEffect(() => {
    const hasRunningWafTest = [...candidates, ...encodingCandidates, ...crossCandidates]
      .some((candidate) => candidate.latest_waf_test?.status === 'queued' || candidate.latest_waf_test?.status === 'running')
    if (!hasRunningWafTest) return
    let cancelled = false
    let timer: number | undefined
    const poll = async () => {
      await refreshActiveWafRuns()
      if (!cancelled) timer = window.setTimeout(poll, document.hidden ? 8000 : 3000)
    }
    timer = window.setTimeout(poll, 3000)
    return () => {
      cancelled = true
      if (timer !== undefined) window.clearTimeout(timer)
    }
  }, [candidates, encodingCandidates, crossCandidates])

  useEffect(() => {
    if (workspace === 'agent' && agentDocuments.length === 0) void loadAgentDocuments()
  }, [workspace, agentDocuments.length])

  useEffect(() => {
    if (workspace === 'encoding' && encodingDocuments.length === 0) void loadEncodingDocuments()
  }, [workspace, encodingDocuments.length])

  useEffect(() => {
    if (!activeTask || !['queued', 'running'].includes(activeTask.status)) return
    const timer = window.setInterval(() => {
      if (semanticPollPromise.current) return
      const request = (async () => {
      try {
        const task = await api<IterationTask>(`/semantic-iterations/${activeTask.id}`)
        setActiveTask(task)
        if (!['queued', 'running'].includes(task.status)) {
          setGenerating(false)
          await loadData()
        }
      } catch (error) {
        if (error instanceof Error && error.message.includes('请求超时')) return
        setGenerating(false)
        setApiError(error instanceof Error ? error.message : '无法获取生成任务状态')
      }
      })()
      semanticPollPromise.current = request
      void request.finally(() => {
        if (semanticPollPromise.current === request) semanticPollPromise.current = null
      })
    }, document.hidden ? 5000 : 2000)
    return () => window.clearInterval(timer)
  }, [activeTask])

  useEffect(() => {
    if (!activeEncodingTask || !['queued', 'running'].includes(activeEncodingTask.status)) return
    const timer = window.setInterval(() => {
      if (encodingPollPromise.current) return
      const request = (async () => {
      try {
        const task = await api<EncodingTask>(`/encoding-iterations/${activeEncodingTask.id}`)
        setActiveEncodingTask(task)
        if (!['queued', 'running'].includes(task.status)) {
          setEncodingGenerating(false)
          await loadData()
        }
      } catch (error) {
        if (error instanceof Error && error.message.includes('请求超时')) return
        setEncodingGenerating(false)
        setApiError(error instanceof Error ? error.message : '无法获取编码生成任务状态')
      }
      })()
      encodingPollPromise.current = request
      void request.finally(() => {
        if (encodingPollPromise.current === request) encodingPollPromise.current = null
      })
    }, document.hidden ? 5000 : 2000)
    return () => window.clearInterval(timer)
  }, [activeEncodingTask])

  const setVulnerability = (vulnerability: VulnerabilityKey) => {
    setDraft((current) => ({
      ...current,
      vulnerability,
      category: vulnerabilityDefinitions[vulnerability].types[0],
      delivery: deliveryFor(vulnerability),
    }))
  }

  const setTarget = (target: string) => {
    setDraft((current) => ({ ...current, target, difficulty: targetDifficulties[target][0] }))
  }

  const createPayload = async () => {
    if (!draft.name.trim() || !draft.content.trim() || !draft.usage_method.trim() || !draft.success_indicators.trim()) return
    try {
      await api<Payload>('/payloads', { method: 'POST', body: JSON.stringify({ ...draft, name: draft.name.trim() }) })
      setDraft((current) => ({ ...current, name: '', content: '', usage_method: '', success_indicators: '' }))
      await loadData()
      setLibraryTab(draft.vulnerability)
      messageApi.success('Payload 已保存到本地库')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '保存失败')
    }
  }

  const beginEdit = (payload: Payload) => {
    setEditingId(payload.id)
    setExpandedCard(payload.id)
    setEditDraft({
      name: payload.name,
      content: payload.content,
      delivery: payload.delivery,
      usage_method: payload.usage_method,
      success_indicators: payload.success_indicators,
    })
  }

  const addToIterationPool = async (agent: 'semantic' | 'encoding', payload: Payload) => {
    try {
      await api<IterationPoolItem>(`/iteration-pools/${agent}`, {
        method: 'POST',
        body: JSON.stringify({ source_payload_id: payload.id }),
      })
      await loadData()
      messageApi.success(`已加入${agent === 'semantic' ? '语义' : '编码'}待迭代池`)
    } catch (error) {
      const detail = error instanceof Error ? error.message : '加入待迭代池失败'
      await loadData()
      if (detail.includes('待启动的迭代池条目')) {
        if (agent === 'semantic') {
          setAgentTab('workspace')
          setWorkspace('agent')
        } else {
          setEncodingAgentTab('workspace')
          setWorkspace('encoding')
        }
        messageApi.warning('该 Payload 已有待启动条目，已为你定位，可直接重新迭代')
        return
      }
      messageApi.error(detail)
    }
  }

  const saveEdit = async (payload: Payload) => {
    if (!editDraft?.name.trim() || !editDraft.content.trim() || !editDraft.usage_method.trim() || !editDraft.success_indicators.trim()) return
    try {
      await api<Payload>(`/payloads/${payload.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          name: editDraft.name.trim(),
          content: editDraft.content,
          delivery: editDraft.delivery,
          usage_method: editDraft.usage_method.trim(),
          success_indicators: editDraft.success_indicators.trim(),
        }),
      })
      setEditingId(null)
      setEditDraft(null)
      await loadData()
      messageApi.success('条目已更新')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '更新失败')
    }
  }

  const deletePayload = async (payload: Payload) => {
    try {
      await api<void>(`/payloads/${payload.id}`, { method: 'DELETE' })
      if (editingId === payload.id) setEditingId(null)
      if (expandedCard === payload.id) setExpandedCard(null)
      await loadData()
      messageApi.success('条目已删除')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '删除失败')
    }
  }

  const startGeneration = async () => {
    if (!selectedBaseId) return
    setGenerating(true)
    try {
      const task = await api<{ id: string; status: 'queued'; candidate_count: number }>('/semantic-iterations', {
        method: 'POST',
        body: JSON.stringify({ base_payload_id: selectedBaseId, candidate_count: candidateCount }),
      })
      setActiveTask({ id: task.id, status: task.status, candidate_count: task.candidate_count, candidates: [] })
      messageApi.info('生成任务已进入队列，不会向任何目标发包')
    } catch (error) {
      setGenerating(false)
      messageApi.error(error instanceof Error ? error.message : '创建任务失败')
    }
  }

  const startEncodingGeneration = async () => {
    if (!selectedEncodingBaseId) return
    setEncodingGenerating(true)
    try {
      const task = await api<{ id: string; status: 'queued'; candidate_count: number }>('/encoding-iterations', {
        method: 'POST',
        body: JSON.stringify({ base_payload_id: selectedEncodingBaseId, candidate_count: encodingCandidateCount }),
      })
      setActiveEncodingTask({ id: task.id, status: task.status, candidate_count: task.candidate_count, candidates: [] })
      messageApi.info('编码任务已进入队列，不会向任何目标发包')
    } catch (error) {
      setEncodingGenerating(false)
      messageApi.error(error instanceof Error ? error.message : '创建编码任务失败')
    }
  }

  const startPoolItem = async (item: IterationPoolItem) => {
    const isSemantic = item.agent === 'semantic'
    const count = isSemantic ? candidateCount : encodingCandidateCount
    const markStarted = (items: IterationPoolItem[]) => items.map((current) => current.id === item.id
      ? { ...current, status: 'started' as const, task_status: 'queued' as const, task_error: null }
      : current)
    if (isSemantic) {
      setSemanticPool(markStarted)
      setGenerating(true)
    } else {
      setEncodingPool(markStarted)
      setEncodingGenerating(true)
    }
    try {
      const task = await api<IterationTask | EncodingTask>(`/iteration-pools/${item.id}/start`, {
        method: 'POST',
        body: JSON.stringify({ candidate_count: count }),
      })
      if (isSemantic) {
        setActiveTask({ ...task, candidates: [] })
        setGenerating(['queued', 'running'].includes(task.status))
      } else {
        setActiveEncodingTask({ ...task, candidates: [] })
        setEncodingGenerating(['queued', 'running'].includes(task.status))
      }
      await loadData()
      if (task.status === 'failed') {
        messageApi.error(task.error_message || '迭代任务失败，可在待迭代池中直接重试')
      } else {
        messageApi.info('迭代任务已启动，不会向任何目标发包')
      }
    } catch (error) {
      if (isSemantic) setGenerating(false)
      else setEncodingGenerating(false)
      await loadData()
      messageApi.error(error instanceof Error ? error.message : '启动待迭代池条目失败')
    }
  }

  const removePoolItem = async (item: IterationPoolItem) => {
    try {
      await api<void>(`/iteration-pools/${item.id}`, { method: 'DELETE' })
      await loadData()
      messageApi.success('条目已移出待迭代池')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '移出待迭代池失败')
    }
  }

  const copyCandidatePayload = async (content: string) => {
    const legacyCopy = () => {
      const textarea = document.createElement('textarea')
      textarea.value = content
      textarea.setAttribute('readonly', '')
      textarea.style.position = 'fixed'
      textarea.style.opacity = '0'
      document.body.appendChild(textarea)
      textarea.select()
      const copied = document.execCommand('copy')
      textarea.remove()
      if (!copied) throw new Error('clipboard unavailable')
    }
    try {
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(content)
      else legacyCopy()
      messageApi.success('候选 Payload 已复制')
    } catch {
      try {
        legacyCopy()
        messageApi.success('候选 Payload 已复制')
      } catch {
        messageApi.error('复制失败，请手动复制内容')
      }
    }
  }

  const directionsByContent = new Map([...candidates, ...encodingCandidates].map((candidate) => [candidate.content, { used: candidate.used_direction_ids, next: candidate.next_directions }]))
  const semanticCandidatesByContent = new Map(candidates.map((candidate) => [candidate.content, candidate]))
  const wafCandidatesByContent = new Map<string, { agent: 'semantic' | 'encoding' | 'cross'; id: string; target: string; vulnerability: VulnerabilityKey; latest?: WafTestRun | null }>([
    ...candidates.map((candidate) => [candidate.content, { agent: 'semantic' as const, id: candidate.id, target: candidate.base_target, vulnerability: candidate.base_vulnerability, latest: candidate.latest_waf_test }] as const),
    ...encodingCandidates.map((candidate) => [candidate.content, { agent: 'encoding' as const, id: candidate.id, target: candidate.base_target, vulnerability: candidate.base_vulnerability, latest: candidate.latest_waf_test }] as const),
    ...crossCandidates.map((candidate) => [candidate.content, { agent: 'cross' as const, id: candidate.id, target: candidate.source_target, vulnerability: candidate.source_vulnerability, latest: candidate.latest_waf_test }] as const),
  ])
  const candidatePayloadBlock = (label: string, content: string) => <div className="candidate-payload-block">
    <div className="candidate-content-heading"><Text type="secondary">{label}</Text><Button className="candidate-copy-button" type="text" size="small" icon={<CopyOutlined />} aria-label={`复制${label}`} title={`复制${label}`} onClick={(event) => { event.stopPropagation(); void copyCandidatePayload(content) }} /></div>
    <pre className="candidate-content">{content}</pre>{semanticCandidatesByContent.has(content) && semanticCandidateReview(semanticCandidatesByContent.get(content)!)}{directionsByContent.has(content) && iterationDirections(directionsByContent.get(content)?.used, directionsByContent.get(content)?.next)}{(() => { const test = wafCandidatesByContent.get(content); return test && <div className="waf-candidate-action">{[...['command-injection', 'sql-injection', 'xss'], ...(wafScene?.direct_targets ? Object.keys(wafScene.direct_targets) : [])].includes(test.vulnerability) ? <Button size="small" type="primary" icon={<SafetyCertificateOutlined />} loading={test.latest?.status === 'queued' || test.latest?.status === 'running'} onClick={() => void sendToWaf(test.agent, test.id)}>发送到 WAF 测试场</Button> : <Text type="secondary">该候选漏洞类型暂不支持自动测试</Text>}{test.latest && <Tag color={test.latest.result === 'execution_confirmed' ? 'green' : test.latest.result === 'waf_blocked' || test.latest.result === 'waf_bypassed' ? 'red' : 'blue'}>{test.latest.result || test.latest.status}</Tag>}</div> })()}
  </div>
  const iterationDirections = (used: string[] = [], next: IterationDirection[] = []) => <div className="iteration-directions">
    <div><Text type="secondary">本轮已使用方向</Text><div className="direction-tags">{used.length ? used.map((id) => <Tag color="blue" key={id}>{id}</Tag>) : <Text type="secondary">暂无</Text>}</div></div>
    <div><Text type="secondary">下一轮 AI 思考方向</Text><div className="direction-tags">{next.length ? next.map((direction) => <Tag color="cyan" key={direction.id} title={direction.reason}>{direction.label}</Tag>) : <Text type="secondary">暂无可用方向</Text>}</div>{next.length > 0 && <Text type="secondary" className="direction-reason">{next.map((direction) => `${direction.label}：${direction.reason}`).join('；')}</Text>}</div>
  </div>

  const semanticCandidateReview = (candidate: Candidate) => {
    const parts = (label: string, items: SemanticPart[] | undefined) => <div className="semantic-part-section"><Text type="secondary">{label}</Text><div className="semantic-part-tags">{items?.length ? items.map((part) => <Tag key={part.part_id} color={part.required ? 'blue' : 'default'} title={part.semantic_role}>{part.part_type}: {part.raw || '（空）'}{part.required ? ' · 必选' : ''}</Tag>) : <Text type="secondary">未提供可审阅的部件快照</Text>}</div></div>
    const operations = candidate.part_operations || []
    const changed = candidate.semantic_delta?.changed_parts || []
    return <div className="semantic-review">
      <div className="semantic-part-section"><Text type="secondary">解析状态</Text><div className="semantic-part-tags"><Tag color={candidate.parser_status === 'supported' ? 'green' : 'orange'}>{candidate.parser_status || 'legacy/manual-verification'}</Tag>{typeof candidate.parser_confidence === 'number' && <Tag>置信度 {Math.round(candidate.parser_confidence * 100)}%</Tag>}</div>{candidate.unsupported_reason && <Paragraph type="secondary">{candidate.unsupported_reason}</Paragraph>}</div>
      {parts('基础 Payload 部件（只读）', candidate.base_parts)}
      {parts('候选 Payload 部件（只读）', candidate.candidate_parts)}
      <div className="semantic-part-section"><Text type="secondary">部件操作记录</Text><div className="semantic-part-tags">{operations.length ? operations.map((operation, index) => <Tag key={`${operation.part_id}-${index}`} color="purple">{operation.operation} · {operation.part_type} · {operation.part_id}</Tag>) : <Text type="secondary">历史候选未提供结构化操作记录，需人工复核。</Text>}</div></div>
      <div className="semantic-part-section"><Text type="secondary">审核摘要</Text><Paragraph>{candidate.semantic_delta?.summary || '未提供结构化语义差异。'}</Paragraph><div className="semantic-part-tags">{changed.map((part) => <Tag key={part}>变更：{part}</Tag>)}{candidate.semantic_delta?.target_preserved === true && <Tag color="green">基础目标已保留</Tag>}{candidate.semantic_delta?.context_preserved === true && <Tag color="green">上下文已保留</Tag>}</div></div>
      {candidate.verification_spec && <div className="semantic-part-section"><Text type="secondary">人工验证规则</Text><pre className="candidate-content">{JSON.stringify(candidate.verification_spec, null, 2)}</pre></div>}
    </div>
  }

  const updateCandidate = async (candidate: Candidate, status: CandidateStatus) => {
    try {
      await api<Candidate>(`/candidates/${candidate.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status, test_note: testNotes[candidate.id] ?? candidate.test_note ?? null }),
      })
      await loadData()
      messageApi.success('候选状态已更新')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '状态更新失败')
    }
  }

  const deleteCandidate = async (candidate: Candidate) => {
    setCandidates((current) => current.filter((item) => item.id !== candidate.id))
    if (expandedCandidate === candidate.id) setExpandedCandidate(null)
    try {
      await api<void>(`/candidates/${candidate.id}`, { method: 'DELETE' })
      await loadData()
      messageApi.success('候选条目已删除')
    } catch (error) {
      await loadData()
      messageApi.error(error instanceof Error ? error.message : '候选删除失败')
    }
  }

  const archiveCandidate = async (candidate: Candidate) => {
    const archiveKey = `semantic:${candidate.id}`
    setArchivingCandidateKey(archiveKey)
    try {
      const archived = await api<Payload>(`/candidates/${candidate.id}/archive`, { method: 'POST' })
      setCandidates((current) => current.map((item) => item.id === candidate.id ? { ...item, status: 'archived' } : item))
      if (expandedCandidate === candidate.id) setExpandedCandidate(null)
      mergeArchivedPayload(archived)
      messageApi.success(`候选已按${archived.archive_outcome === 'bypass_failure' ? '绕过失败' : '绕过成功'}结果归档`)
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '归档失败')
    } finally {
      setArchivingCandidateKey((current) => current === archiveKey ? null : current)
    }
  }

  const updateEncodingCandidate = async (candidate: EncodingCandidate, status: CandidateStatus) => {
    try {
      await api<EncodingCandidate>(`/encoding-candidates/${candidate.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status, test_note: encodingTestNotes[candidate.id] ?? candidate.test_note ?? null }),
      })
      await loadData()
      messageApi.success('编码候选状态已更新')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '编码候选状态更新失败')
    }
  }

  const deleteEncodingCandidate = async (candidate: EncodingCandidate) => {
    try {
      await api<void>(`/encoding-candidates/${candidate.id}`, { method: 'DELETE' })
      if (expandedEncodingCandidate === candidate.id) setExpandedEncodingCandidate(null)
      await loadData()
      messageApi.success('编码候选已删除')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '编码候选删除失败')
    }
  }

  const archiveEncodingCandidate = async (candidate: EncodingCandidate) => {
    const archiveKey = `encoding:${candidate.id}`
    setArchivingCandidateKey(archiveKey)
    try {
      const archived = await api<Payload>(`/encoding-candidates/${candidate.id}/archive`, { method: 'POST' })
      setEncodingCandidates((current) => current.map((item) => item.id === candidate.id ? { ...item, status: 'archived' } : item))
      if (expandedEncodingCandidate === candidate.id) setExpandedEncodingCandidate(null)
      mergeArchivedPayload(archived)
      messageApi.success(`编码候选已按${archived.archive_outcome === 'bypass_failure' ? '绕过失败' : '绕过成功'}结果归档`)
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '编码候选归档失败')
    } finally {
      setArchivingCandidateKey((current) => current === archiveKey ? null : current)
    }
  }

  const archiveCandidateControls = (
    candidate: Candidate | EncodingCandidate,
    agent: 'semantic' | 'encoding',
  ) => {
    if (candidate.status !== 'test_success' && candidate.status !== 'test_failed') return null
    const succeeded = candidate.status === 'test_success'
    const archiveKey = `${agent}:${candidate.id}`
    const cancel = agent === 'semantic'
      ? () => updateCandidate(candidate as Candidate, 'pending_test')
      : () => updateEncodingCandidate(candidate as EncodingCandidate, 'pending_test')
    const archive = agent === 'semantic'
      ? () => archiveCandidate(candidate as Candidate)
      : () => archiveEncodingCandidate(candidate as EncodingCandidate)
    const description = succeeded
      ? agent === 'semantic'
        ? '归档后会进入成功样例和待交叉来源。'
        : '归档后会进入成功样例，并保留编码链来源。'
      : '仅保存到 Payload 库，不会进入成功样例或后续迭代。'
    return <Space>
      <Button size="small" disabled={archivingCandidateKey === archiveKey} onClick={() => void cancel()}>
        {succeeded ? '取消成功标记' : '取消失败标记'}
      </Button>
      <Popconfirm
        title={`以${succeeded ? '绕过成功' : '绕过失败'}结果归档？`}
        description={description}
        okButtonProps={{ danger: !succeeded }}
        onConfirm={() => void archive()}
      >
        <Button
          type="primary"
          danger={!succeeded}
          size="small"
          loading={archivingCandidateKey === archiveKey}
        >
          归档到 Payload 库
        </Button>
      </Popconfirm>
    </Space>
  }

  const startCrossGeneration = async () => {
    if (!selectedCrossSourceId) return
    setCrossGenerating(true)
    try {
      const task = await api<CrossTask>('/cross-iterations', {
        method: 'POST',
        body: JSON.stringify({ cross_source_id: selectedCrossSourceId, candidate_count: crossCandidateCount }),
      })
      const detail = await api<CrossTask>(`/cross-iterations/${task.id}`)
      setActiveCrossTask(detail)
      await loadData()
      messageApi.success('正向交叉候选已生成，全程未向任何目标发包')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '创建正向交叉任务失败')
    } finally {
      setCrossGenerating(false)
    }
  }

  const updateCrossCandidate = async (candidate: CrossCandidate, status: CandidateStatus) => {
    try {
      await api<CrossCandidate>(`/cross-candidates/${candidate.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status, test_note: crossTestNotes[candidate.id] ?? candidate.test_note ?? null }),
      })
      await loadData()
      messageApi.success(status === 'test_success' ? '候选已存入成功样例' : '正向交叉候选状态已更新')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '正向交叉候选状态更新失败')
    }
  }

  const deleteCrossCandidate = async (candidate: CrossCandidate) => {
    try {
      await api<void>(`/cross-candidates/${candidate.id}`, { method: 'DELETE' })
      if (expandedCrossCandidate === candidate.id) setExpandedCrossCandidate(null)
      await loadData()
      messageApi.success('正向交叉候选已删除，编码链仍会保留为历史记录')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '正向交叉候选删除失败')
    }
  }

  const deleteSuccessSample = async (sample: SuccessSample) => {
    try {
      await api<void>(`/success-samples/${sample.id}`, { method: 'DELETE' })
      if (expandedSample === sample.id) setExpandedSample(null)
      await loadData()
      messageApi.success('成功样例已从样例库移除')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '成功样例删除失败')
    }
  }

  const mergeReport = (updated: Report) => {
    setReports((current) => [updated, ...current.filter((report) => report.id !== updated.id)])
  }

  const saveReport = async (snapshot = reportDraft, notify = false) => {
    if (!snapshot) return false
    if (reportAutoSaveTimer.current !== null) {
      window.clearTimeout(reportAutoSaveTimer.current)
      reportAutoSaveTimer.current = null
    }
    const revision = reportSaveRevision.current
    setReportSaveState('saving')
    try {
      const updated = await api<Report>(`/reports/${snapshot.id}`, {
        method: 'PATCH',
        body: JSON.stringify(reportUpdatePayload(snapshot)),
      })
      mergeReport(updated)
      if (reportSaveRevision.current === revision) {
        setReportDraft(updated)
        setReportSaveState('saved')
      }
      if (notify) messageApi.success('报告已保存')
      return true
    } catch (error) {
      if (reportSaveRevision.current === revision) setReportSaveState('error')
      messageApi.error(error instanceof Error ? error.message : '报告保存失败')
      return false
    }
  }

  const updateReportField = (field: ReportEditableField, value: string) => {
    if (!reportDraft) return
    const updated = { ...reportDraft, [field]: value }
    reportSaveRevision.current += 1
    setReportDraft(updated)
    setReportSaveState('dirty')
    if (reportAutoSaveTimer.current !== null) window.clearTimeout(reportAutoSaveTimer.current)
    reportAutoSaveTimer.current = window.setTimeout(() => {
      void saveReport(updated)
    }, 800)
  }

  const selectReport = async (report: Report) => {
    if (reportDraft?.id !== report.id && reportSaveState === 'dirty') {
      const saved = await saveReport(reportDraft)
      if (!saved) return
    }
    if (reportAutoSaveTimer.current !== null) window.clearTimeout(reportAutoSaveTimer.current)
    reportSaveRevision.current += 1
    setSelectedReportId(report.id)
    setReportDraft(report)
    setReportSaveState('saved')
  }

  const openSampleReport = async (sample: SuccessSample) => {
    try {
      const report = await api<Report>(`/reports/from-sample/${sample.id}`, { method: 'POST' })
      mergeReport(report)
      setSelectedReportId(report.id)
      setReportDraft(report)
      setReportSaveState('saved')
      setReportTab('edit')
      setWorkspace('reports')
      messageApi.success(reports.some((item) => item.success_sample_id === sample.id) ? '已打开现有报告' : '报告草稿已创建')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '创建报告失败')
    }
  }

  const refreshReport = async (reportId: string) => {
    const updated = await api<Report>(`/reports/${reportId}`)
    mergeReport(updated)
    if (selectedReportId === reportId) setReportDraft(updated)
    return updated
  }

  const deleteReport = async (report: Report) => {
    try {
      await api<void>(`/reports/${report.id}`, { method: 'DELETE' })
      const remaining = reports.filter((item) => item.id !== report.id)
      setReports(remaining)
      setSelectedReportId(remaining[0]?.id || null)
      setReportDraft(remaining[0] || null)
      setReportSaveState('saved')
      messageApi.success('报告及其验证图片已删除')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '删除报告失败')
    }
  }

  const uploadReportImages = async (files: File[]) => {
    if (!reportDraft || files.length === 0) return
    setReportUploading(true)
    try {
      for (const file of files) {
        const form = new FormData()
        form.append('file', file)
        await api<ReportImage>(`/reports/${reportDraft.id}/images`, { method: 'POST', body: form })
      }
      await refreshReport(reportDraft.id)
      messageApi.success(`${files.length} 张验证图片已加入报告`)
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '验证图片上传失败')
    } finally {
      setReportUploading(false)
    }
  }

  const pasteReportImages = (event: React.ClipboardEvent<HTMLDivElement>) => {
    event.preventDefault()
    const files = Array.from(event.clipboardData.items)
      .filter((item) => item.kind === 'file' && item.type.startsWith('image/'))
      .map((item) => item.getAsFile())
      .filter((file): file is File => Boolean(file))
    if (!files.length) {
      messageApi.warning('剪贴板中没有可用的图片')
      return
    }
    void uploadReportImages(files)
  }

  const updateReportImageCaption = (imageId: string, caption: string) => {
    setReportDraft((current) => current ? {
      ...current,
      images: current.images.map((image) => image.id === imageId ? { ...image, caption } : image),
    } : current)
  }

  const saveReportImage = async (image: ReportImage, changes: Partial<Pick<ReportImage, 'caption' | 'sort_order'>>) => {
    try {
      await api<ReportImage>(`/report-images/${image.id}`, {
        method: 'PATCH',
        body: JSON.stringify(changes),
      })
      if (reportDraft) await refreshReport(reportDraft.id)
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '图片信息更新失败')
    }
  }

  const moveReportImage = async (image: ReportImage, direction: -1 | 1) => {
    if (!reportDraft) return
    const ordered = [...reportDraft.images].sort((left, right) => left.sort_order - right.sort_order)
    const currentIndex = ordered.findIndex((item) => item.id === image.id)
    const targetIndex = currentIndex + direction
    if (currentIndex < 0 || targetIndex < 0 || targetIndex >= ordered.length) return
    try {
      await Promise.all([
        api<ReportImage>(`/report-images/${ordered[currentIndex].id}`, { method: 'PATCH', body: JSON.stringify({ sort_order: targetIndex }) }),
        api<ReportImage>(`/report-images/${ordered[targetIndex].id}`, { method: 'PATCH', body: JSON.stringify({ sort_order: currentIndex }) }),
      ])
      await refreshReport(reportDraft.id)
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '图片排序失败')
    }
  }

  const deleteReportImage = async (image: ReportImage) => {
    try {
      await api<void>(`/report-images/${image.id}`, { method: 'DELETE' })
      if (reportDraft) await refreshReport(reportDraft.id)
      messageApi.success('验证图片已删除')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '删除验证图片失败')
    }
  }

  const dashboardMetrics = useMemo(() => {
    if (dashboardSummary) {
      return {
        payloadCount: dashboardSummary.payload_count,
        successSampleCount: dashboardSummary.success_sample_count,
        semanticPoolPending: dashboardSummary.semantic_pool_pending,
        encodingPoolPending: dashboardSummary.encoding_pool_pending,
        pendingPoolCount: dashboardSummary.semantic_pool_pending + dashboardSummary.encoding_pool_pending,
        agents: dashboardSummary.agents,
        success: dashboardSummary.success,
        failed: dashboardSummary.failed,
        completed: dashboardSummary.completed,
        pending: dashboardSummary.pending,
        rate: dashboardSummary.rate,
      }
    }
    const summarize = (items: Array<{ status: CandidateStatus }>) => {
      const pending = items.filter((item) => item.status === 'pending_test').length
      const success = items.filter((item) => item.status === 'test_success' || item.status === 'archived').length
      const failed = items.filter((item) => item.status === 'test_failed' || item.status === 'rejected').length
      const completed = success + failed
      return { pending, success, failed, completed, rate: completed ? (success / completed) * 100 : null }
    }
    const agents = {
      semantic: summarize(candidates),
      encoding: summarize(encodingCandidates),
      cross: summarize(crossCandidates),
    }
    const success = agents.semantic.success + agents.encoding.success + agents.cross.success
    const failed = agents.semantic.failed + agents.encoding.failed + agents.cross.failed
    const completed = success + failed
    const semanticPoolPending = retryablePoolItems(semanticPool).length
    const encodingPoolPending = retryablePoolItems(encodingPool).length
    return {
      payloadCount: payloads.length,
      successSampleCount: successSamples.length,
      semanticPoolPending,
      encodingPoolPending,
      pendingPoolCount: semanticPoolPending + encodingPoolPending,
      agents,
      success,
      failed,
      completed,
      pending: agents.semantic.pending + agents.encoding.pending + agents.cross.pending,
      rate: completed ? (success / completed) * 100 : null,
    }
  }, [candidates, dashboardSummary, encodingCandidates, crossCandidates, payloads.length, successSamples.length, semanticPool, encodingPool])

  const pageControl = (key: keyof typeof page) => {
    const totalKey = key as keyof typeof totals
    return totals[totalKey] > PAGE_SIZE ? <Pagination
      className="list-pagination"
      size="small"
      current={page[key]}
      pageSize={PAGE_SIZE}
      total={totals[totalKey]}
      showSizeChanger={false}
      onChange={(next) => setPage((current) => ({ ...current, [key]: next }))}
    /> : null
  }

  const dashboardFlowNode = (label: string, meta: string, className: string, target?: WorkspaceKey) => {
    const content = <><strong>{label}</strong><span>{meta}</span></>
    return target
      ? <button type="button" className={`dashboard-flow-node ${className} dashboard-flow-node-clickable`} onClick={() => setWorkspace(target)}>{content}</button>
      : <div className={`dashboard-flow-node ${className}`}>{content}</div>
  }

  const dashboardAgentRows = [
    { key: 'semantic', label: '语义迭代 Agent', color: 'blue', ...dashboardMetrics.agents.semantic },
    { key: 'encoding', label: '编码绕过 Agent', color: 'cyan', ...dashboardMetrics.agents.encoding },
    { key: 'cross', label: '正向交叉迭代', color: 'purple', ...dashboardMetrics.agents.cross },
  ]
  const dashboardAgentColumns = [
    { title: '处理单元', dataIndex: 'label', key: 'label', render: (label: string, row: { color: string }) => <Tag color={row.color}>{label}</Tag> },
    { title: '待测试', dataIndex: 'pending', key: 'pending', width: 90 },
    { title: '成功', dataIndex: 'success', key: 'success', width: 80, render: (value: number) => <Text type="success">{value}</Text> },
    { title: '失败 / 拒绝', dataIndex: 'failed', key: 'failed', width: 105, render: (value: number) => <Text type={value ? 'danger' : 'secondary'}>{value}</Text> },
    { title: '有效率', dataIndex: 'rate', key: 'rate', width: 120, render: (value: number | null) => value === null ? <Text type="secondary">暂无闭环数据</Text> : <Text strong>{value.toFixed(1)}%</Text> },
  ]

  const dashboardWorkspace = workspace === 'dashboard' && <section className="workspace-card dashboard-workspace">
    <div className="dashboard-heading">
      <div>
        <Title level={4}>项目仪表盘</Title>
        <Text type="secondary">Payload 迭代闭环与人工测试状态总览</Text>
      </div>
      <Tag color="blue">本地工作台</Tag>
    </div>

    <div className="dashboard-kpi-grid">
      <Card className="dashboard-kpi-card" size="small"><Statistic title="正式 Payload" value={dashboardMetrics.payloadCount} suffix="条" prefix={<DatabaseOutlined />} /></Card>
      <Card className="dashboard-kpi-card" size="small"><Statistic title="语义待测试" value={dashboardMetrics.agents.semantic.pending} suffix="条" prefix={<ApiOutlined />} /></Card>
      <Card className="dashboard-kpi-card" size="small"><Statistic title="编码待测试" value={dashboardMetrics.agents.encoding.pending} suffix="条" prefix={<CodeOutlined />} /></Card>
      <Card className="dashboard-kpi-card" size="small"><Statistic title="正向交叉待测试" value={dashboardMetrics.agents.cross.pending} suffix="条" prefix={<ApartmentOutlined />} /></Card>
      <Card className="dashboard-kpi-card" size="small"><Statistic title="成功样例" value={dashboardMetrics.successSampleCount} suffix="条" prefix={<TrophyOutlined />} /></Card>
    </div>

    <div className="dashboard-main-grid">
      <div className="dashboard-panel dashboard-flow-panel">
        <div className="dashboard-panel-heading"><div><Title level={5}>迭代流程</Title><Text type="secondary">点击可跳转节点进入对应工作区</Text></div><Tag color="blue">闭环流程</Tag></div>
        <div className="dashboard-flow-scroll">
          <div className="dashboard-flow-canvas">
            <svg className="dashboard-flow-lines" viewBox="0 0 1090 430" preserveAspectRatio="none" aria-hidden="true">
              <defs><marker id="dashboard-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#1890ff" /></marker></defs>
              <path d="M185 207 L220 207 L220 107 L250 107" />
              <path d="M185 207 L220 207 L220 307 L250 307" />
              <path d="M410 107 L450 107 L450 207 L480 207" />
              <path d="M410 307 L450 307 L450 207 L480 207" />
              <path d="M640 207 L690 207" />
              <path d="M850 207 L875 207 L875 107 L900 107" />
              <path d="M850 207 L875 207 L875 307 L900 307" />
              <path d="M975 339 L975 400 L80 400 L80 239" />
            </svg>
            {dashboardFlowNode('可用 Payload 库', `${dashboardMetrics.payloadCount} 条`, 'dashboard-flow-payload', 'library')}
            {dashboardFlowNode('语义绕过 Agent', `${dashboardMetrics.agents.semantic.pending} 条待测`, 'dashboard-flow-semantic', 'agent')}
            {dashboardFlowNode('编码绕过 Agent', `${dashboardMetrics.agents.encoding.pending} 条待测`, 'dashboard-flow-encoding', 'encoding')}
            {dashboardFlowNode('正向交叉', `${dashboardMetrics.agents.cross.pending} 条待测`, 'dashboard-flow-cross', 'cross')}
            {dashboardFlowNode('WAF 测试场', `${dashboardMetrics.pending} 条候选待测试`, 'dashboard-flow-test', 'waf')}
            <div className="dashboard-flow-outcome dashboard-flow-failure-left"><strong>失败 / 拒绝</strong><span>{dashboardMetrics.failed} 条</span></div>
            <div className="dashboard-flow-outcome dashboard-flow-success"><strong>成功</strong><span>{dashboardMetrics.success} 条</span></div>
            <div className="dashboard-flow-outcome dashboard-flow-failure-right"><strong>失败 / 拒绝</strong><span>{dashboardMetrics.failed} 条</span></div>
            {dashboardFlowNode('报告 / 成功样例', `${dashboardMetrics.successSampleCount} 条 active`, 'dashboard-flow-report', 'samples')}
          </div>
        </div>
      </div>

      <div className="dashboard-side-stack">
        <div className="dashboard-panel dashboard-rate-panel">
          <div className="dashboard-panel-heading"><div><Title level={5}>迭代有效率</Title><Text type="secondary">仅统计已完成人工测试的候选</Text></div></div>
          <div className="dashboard-rate-content">
            {dashboardMetrics.rate === null ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无闭环数据" /> : <><Progress type="circle" percent={dashboardMetrics.rate} size={132} strokeColor="#1677ff" format={(percent) => `${percent?.toFixed(1)}%`} /><div className="dashboard-rate-meta"><Text strong>{dashboardMetrics.success} 条成功</Text><Text type="secondary">/ {dashboardMetrics.completed} 条已完成</Text><Text type="secondary">待测试 {dashboardMetrics.pending} 条</Text></div></>}
          </div>
        </div>
        <div className="dashboard-panel dashboard-pool-panel">
          <div className="dashboard-panel-heading"><div><Title level={5}>待迭代池</Title><Text type="secondary">等待手工启动的输入条目</Text></div><Tag color={dashboardMetrics.pendingPoolCount ? 'orange' : 'default'}>{dashboardMetrics.pendingPoolCount} 条</Tag></div>
          <div className="dashboard-pool-row"><span>语义待迭代池</span><strong>{dashboardMetrics.semanticPoolPending}</strong></div>
          <div className="dashboard-pool-row"><span>编码待迭代池</span><strong>{dashboardMetrics.encodingPoolPending}</strong></div>
        </div>
      </div>
    </div>

    <div className="dashboard-panel dashboard-agents-panel">
      <div className="dashboard-panel-heading"><div><Title level={5}>Agent 状态汇总</Title><Text type="secondary">成功率按当前候选状态即时计算</Text></div></div>
      <Table className="dashboard-agent-table" rowKey="key" size="small" pagination={false} columns={dashboardAgentColumns} dataSource={dashboardAgentRows} />
    </div>
  </section>

  const navigationItems: MenuProps['items'] = [
    { type: 'group', label: '概览区', children: [
      { key: 'dashboard', icon: <DashboardOutlined />, label: '项目仪表盘' },
    ] },
    { type: 'group', label: '迭代区', children: [
      { key: 'library', icon: <DatabaseOutlined />, label: 'Payload 库' },
      { key: 'agent', icon: <ApiOutlined />, label: '语义迭代 Agent' },
      { key: 'encoding', icon: <CodeOutlined />, label: '编码绕过 Agent' },
      { key: 'cross', icon: <ApartmentOutlined />, label: '正向交叉迭代' },
    ] },
    { type: 'group', label: '测试区', children: [
      { key: 'waf', icon: <SafetyCertificateOutlined />, label: 'WAF 测试场' },
    ] },
    { type: 'group', label: '结果区', children: [
      { key: 'samples', icon: <TrophyOutlined />, label: '成功样例' },
      { key: 'reports', icon: <FileTextOutlined />, label: '报告撰写' },
      { key: 'curl-tool', icon: <ToolOutlined />, label: 'curl 命令生成器' },
    ] },
  ]

  const sourceTab = (
    <div className="source-workbench-grid">
      <Card className="workbench-card payload-editor-card" title={<Space><FileAddOutlined />源 Payload 编辑器</Space>}>
        <Form className="payload-form" layout="vertical" onFinish={createPayload}>
          <div className="form-grid">
            <Form.Item label="漏洞类型" required>
              <Select value={draft.vulnerability} options={vulnerabilityKeys.map((key) => ({ value: key, label: vulnerabilityDefinitions[key].label }))} onChange={setVulnerability} />
            </Form.Item>
            <Form.Item label="分类" required>
              <Select value={draft.category} options={vulnerabilityDefinitions[draft.vulnerability].types.map((category) => ({ value: category, label: category }))} onChange={(category) => setDraft((current) => ({ ...current, category }))} />
            </Form.Item>
            <Form.Item label="投递方式" required>
              <Select value={draft.delivery} options={deliveryOptions.map((delivery) => ({ value: delivery, label: delivery }))} onChange={(delivery) => setDraft((current) => ({ ...current, delivery }))} />
            </Form.Item>
            <Form.Item label="靶场平台" required>
              <Select value={draft.target} options={['DVWA', 'Pikachu', '通用'].map((target) => ({ value: target, label: target }))} onChange={(target) => setDraft((current) => ({ ...current, target }))} />
            </Form.Item>
          </div>
          <Form.Item label="自定义名称" required><Input value={draft.name} maxLength={64} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} /></Form.Item>
          <Form.Item label="Payload 内容" required><Input.TextArea className="payload-editor" value={draft.content} rows={12} maxLength={5000} showCount onChange={(event) => setDraft((current) => ({ ...current, content: event.target.value }))} /></Form.Item>
          <div className="payload-guidance-form-grid">
            <Form.Item label="使用方法" required><Input.TextArea rows={5} maxLength={3000} showCount value={draft.usage_method} onChange={(event) => setDraft((current) => ({ ...current, usage_method: event.target.value }))} placeholder="填写授权测试环境中的投递步骤、输入位置和注意事项" /></Form.Item>
            <Form.Item label="成功现象 / 验证方式" required><Input.TextArea rows={5} maxLength={3000} showCount value={draft.success_indicators} onChange={(event) => setDraft((current) => ({ ...current, success_indicators: event.target.value }))} placeholder="填写可观察的响应、回显、弹窗、日志或受控回连现象" /></Form.Item>
          </div>
          <div className="form-actions"><Button type="primary" htmlType="submit" icon={<FileAddOutlined />} disabled={!draft.name.trim() || !draft.content.trim() || !draft.usage_method.trim() || !draft.success_indicators.trim()}>保存 Payload</Button></div>
        </Form>
      </Card>
      <Card className="workbench-card terminal-card" title={<Space><CodeOutlined />解析终端</Space>} extra={<span className="terminal-status">● LOCAL</span>}>
        <div className="terminal-window">
          <div className="terminal-line"><span>$</span> target: {draft.target}</div>
          <div className="terminal-line"><span>$</span> vulnerability: {vulnerabilityDefinitions[draft.vulnerability].label}</div>
          <div className="terminal-line"><span>$</span> delivery: {draft.delivery}</div>
          <div className="terminal-divider" /><div className="terminal-muted">内容预览</div><pre>{draft.content || '等待输入 Payload 内容…'}</pre>
        </div>
      </Card>
    </div>
  )

  const sendPayloadToTencentWaf = async (payload: Payload) => {
    try {
      await api<WafTestRun>('/waf-test-runs/direct', {
        method: 'POST',
        body: JSON.stringify({
          target: 'tencent-waf',
          content: payload.content,
          name: payload.name
        })
      })
      await loadData()
      await loadWafData()
      messageApi.success(`"${payload.name}" 已发送到腾讯云测试场`)
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '发送到测试场失败')
    }
  }

  const payloadTab = (vulnerability: VulnerabilityKey) => {
    const definition = vulnerabilityDefinitions[vulnerability]
    const entries = payloads.filter((payload) => payload.vulnerability === vulnerability)
    return <div className="payload-list-layout">
      <div className="panel-heading payload-list-heading"><Space><Title level={5}>{definition.label}</Title><Tag color={definition.tagColor}>{entries.length} 条</Tag></Space></div>
      {entries.length === 0 ? <Card className="empty-card" variant="borderless"><Empty description="暂无已验证 Payload" /></Card> : <>
        <div className="accordion-section-title">条目详情</div>
        <Collapse className="payload-accordion" accordion bordered={false} activeKey={expandedCard ? [expandedCard] : []} onChange={(key) => setExpandedCard(Array.isArray(key) ? key[0] || null : key || null)} items={entries.map((payload) => ({
          key: payload.id,
          label: <div className="payload-card-label"><div><Text strong>{payload.name}</Text><div className="payload-card-meta"><Tag color="blue">{payload.target}</Tag><Tag>{payload.category}</Tag><Tag color="geekblue">{payload.delivery}</Tag>{archiveOutcomeTag(payload.archive_outcome)}<Text type="secondary">{payload.created_at}</Text></div></div><div className="payload-card-actions"><Button type="primary" icon={<SafetyCertificateOutlined />} onClick={(event) => { event.stopPropagation(); void sendPayloadToTencentWaf(payload) }}>发送到测试场</Button><Button type="link" onClick={(event) => { event.stopPropagation(); void addToIterationPool('semantic', payload) }}>加入语义待迭代池</Button>{['command-injection', 'sql-injection', 'xss'].includes(payload.vulnerability) && <Button type="link" onClick={(event) => { event.stopPropagation(); void addToIterationPool('encoding', payload) }}>加入编码待迭代池</Button>}<Button type="link" onClick={(event) => { event.stopPropagation(); beginEdit(payload) }}>修改</Button><Popconfirm title="删除该条目？" onConfirm={() => void deletePayload(payload)}><Button danger type="link" onClick={(event) => event.stopPropagation()}>删除</Button></Popconfirm></div></div>,
          children: editingId === payload.id && editDraft ? <div className="payload-card-editor"><Input value={editDraft.name} onChange={(event) => setEditDraft((current) => current ? { ...current, name: event.target.value } : current)} /><Input.TextArea rows={8} value={editDraft.content} onChange={(event) => setEditDraft((current) => current ? { ...current, content: event.target.value } : current)} /><Select value={editDraft.delivery} options={deliveryOptions.map((delivery) => ({ value: delivery, label: delivery }))} onChange={(delivery) => setEditDraft((current) => current ? { ...current, delivery } : current)} /><div className="payload-guidance-form-grid"><label className="payload-editor-field"><Text type="secondary">使用方法</Text><Input.TextArea rows={5} maxLength={3000} showCount value={editDraft.usage_method} onChange={(event) => setEditDraft((current) => current ? { ...current, usage_method: event.target.value } : current)} /></label><label className="payload-editor-field"><Text type="secondary">成功现象 / 验证方式</Text><Input.TextArea rows={5} maxLength={3000} showCount value={editDraft.success_indicators} onChange={(event) => setEditDraft((current) => current ? { ...current, success_indicators: event.target.value } : current)} /></label></div><Space><Button type="primary" size="small" disabled={!editDraft.name.trim() || !editDraft.content.trim() || !editDraft.usage_method.trim() || !editDraft.success_indicators.trim()} onClick={() => void saveEdit(payload)}>保存修改</Button><Button size="small" onClick={() => { setEditingId(null); setEditDraft(null) }}>取消</Button></Space></div> : <div className="payload-inline-detail">{payload.archive_outcome && <div className="payload-detail-section"><Text type="secondary">归档结果</Text><div>{archiveOutcomeTag(payload.archive_outcome)}</div></div>}<div className="payload-detail-section"><Text type="secondary">Payload 内容</Text><pre>{payload.content}</pre></div><div className="payload-detail-section"><Text type="secondary">使用方法</Text><Paragraph>{payload.usage_method || '待补充使用方法'}</Paragraph></div><div className="payload-detail-section"><Text type="secondary">成功现象 / 验证方式</Text><Paragraph>{payload.success_indicators || '待补充成功验证方式'}</Paragraph></div></div>,
        }))} />
      </>}
      {pageControl('payloads')}
    </div>
  }

  const libraryTabs: TabsProps['items'] = workspace === 'library' ? [
    { key: 'source', label: <span className="tab-label"><FileAddOutlined />源 Payload 添加</span>, children: sourceTab },
    ...vulnerabilityKeys.map((key) => ({ key, label: <span className="tab-label">{vulnerabilityDefinitions[key].icon}{vulnerabilityDefinitions[key].label}</span>, children: payloadTab(key) })),
  ] : []

  const visibleCandidates = useMemo(
    () => candidates.filter((candidate) => !['archived', 'rejected'].includes(candidate.status)),
    [candidates],
  )
  const semanticPendingPool = retryablePoolItems(semanticPool)
  const semanticStartedPool = semanticPool.filter((item) => item.status === 'started' && ['queued', 'running', 'unknown'].includes(item.task_status || 'unknown'))
  const encodingPendingPool = retryablePoolItems(encodingPool)
  const encodingStartedPool = encodingPool.filter((item) => item.status === 'started' && ['queued', 'running', 'unknown'].includes(item.task_status || 'unknown'))
  const renderPoolItems = (items: IterationPoolItem[]) => items.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无待迭代条目" /> : <Collapse className="candidate-accordion" bordered={false} items={items.map((item) => ({
    key: item.id,
    label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong>{item.snapshot.name}</Text><div className="candidate-card-meta"><Tag color={vulnerabilityDefinitions[item.snapshot.vulnerability].tagColor}>{vulnerabilityDefinitions[item.snapshot.vulnerability].label}</Tag><Tag>{item.snapshot.target}</Tag><Tag color="geekblue">{item.snapshot.delivery}</Tag></div></div></div>,
    children: <div className="candidate-detail"><Text type="secondary">快照 Payload</Text><pre className="candidate-content">{item.snapshot.content}</pre>{item.task_status === 'failed' && <Alert type="error" showIcon title="上次迭代失败，可直接重试" description={item.task_error || '模型调用或候选校验失败'} />}{item.task_status === 'completed' && <Alert type="success" showIcon title="上次迭代已完成" description="原候选已保留，可从同一快照继续创建新一轮任务。" />}<Space><Button type="primary" size="small" onClick={() => void startPoolItem(item)}>{item.task_status === 'completed' ? '再次迭代' : item.task_status === 'failed' ? '重新迭代' : '开始迭代'}</Button><Popconfirm title="移出待迭代池？" description="该快照会被删除，不会影响原始 Payload。" onConfirm={() => void removePoolItem(item)}><Button danger size="small">移出池</Button></Popconfirm></Space></div>,
  }))} />
  const selectedDocument = agentDocuments.find((document) => document.id === selectedDocumentId)
  const agentWorkbench = workspace === 'agent' && <div className="agent-workbench">
    {visibleCandidates.some((candidate) => candidate.next_directions?.length) && <Card size="small" className="workbench-card" title="下一轮 AI 思考方向"><Space orientation="vertical" size="small">{visibleCandidates.filter((candidate) => candidate.next_directions?.length).map((candidate) => <div key={candidate.id}><Text strong>{candidate.base_payload_name}</Text>{iterationDirections(candidate.used_direction_ids, candidate.next_directions)}</div>)}</Space></Card>}
    <div className="agent-grid">
      <Card className="workbench-card" title={<Space><ApiOutlined />语义迭代任务</Space>}>
        <Form layout="vertical">
          <Form.Item label="每条生成数量"><Space><InputNumber min={1} max={20} value={candidateCount} onChange={(value) => setCandidateCount(value ?? 5)} disabled={generating} /><Text type="secondary">个候选</Text></Space></Form.Item>
          <div className="pool-heading"><Text strong>待迭代池</Text><Tag color="blue">{semanticPendingPool.length} 条</Tag></div>
          {renderPoolItems(semanticPendingPool)}
        </Form>
      </Card>
      <Card className="workbench-card" title="进行中任务">
        {semanticStartedPool.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无进行中任务" /> : <div className="pool-started-list">{semanticStartedPool.map((item) => <div className="pool-started-item" key={item.id}><Text strong>{item.snapshot.name}</Text><div><Tag color={item.task_status === 'completed' ? 'green' : item.task_status === 'failed' ? 'red' : 'blue'}>{item.task_status || 'queued'}</Tag><Text type="secondary">任务 ID：{item.task_id}</Text></div></div>)}</div>}
        {activeTask && <div className="task-status"><Tag color={activeTask.status === 'completed' ? 'green' : activeTask.status === 'failed' ? 'red' : 'blue'}>{activeTask.status}</Tag><Paragraph>当前任务：{activeTask.id}</Paragraph>{activeTask.status === 'failed' && <Alert type="error" title={activeTask.error_message || '生成失败'} />}</div>}
      </Card>
    </div>
    <div className="queue-heading"><Title level={5}>待测试队列</Title><Tag color="blue">{visibleCandidates.length} 条</Tag></div>
    {visibleCandidates.length === 0 ? <Card className="empty-card" variant="borderless"><Empty description="暂无待测试候选" /></Card> : <Collapse className="candidate-accordion" accordion bordered={false} activeKey={expandedCandidate ? [expandedCandidate] : []} onChange={(key) => setExpandedCandidate(Array.isArray(key) ? key[0] || null : key || null)} items={visibleCandidates.map((candidate) => ({
      key: candidate.id,
      label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong>{candidate.base_payload_name}</Text><div className="candidate-card-meta"><Tag color="blue">{candidate.base_target}</Tag><Tag color="geekblue">{candidate.delivery}</Tag>{candidate.rule_labels.map((label) => <Tag key={label}>{label}</Tag>)}{statusTag(candidate.status)}</div></div><div className="candidate-card-actions" onClick={(event) => event.stopPropagation()}><Popconfirm title="删除该候选条目？" description="删除后无法恢复，且不会影响基础 Payload。" onConfirm={() => void deleteCandidate(candidate)}><Button danger type="link" size="small">删除</Button></Popconfirm></div></div>,
      children: <div className="candidate-detail">{candidatePayloadBlock('候选 Payload', candidate.content)}<Paragraph type="secondary">{candidate.explanation}</Paragraph>{candidate.status === 'pending_test' && <div className="candidate-actions"><Input placeholder="手工测试记录（可选）" value={testNotes[candidate.id] || ''} onClick={(event) => event.stopPropagation()} onChange={(event) => setTestNotes((current) => ({ ...current, [candidate.id]: event.target.value }))} /><Space><Button size="small" type="primary" onClick={() => void updateCandidate(candidate, 'test_success')}>标记测试成功</Button><Button size="small" danger onClick={() => void updateCandidate(candidate, 'test_failed')}>标记测试失败</Button><Button size="small" onClick={() => void updateCandidate(candidate, 'rejected')}>拒绝</Button></Space></div>}{archiveCandidateControls(candidate, 'semantic')}{candidate.test_note && <Paragraph type="secondary">测试记录：{candidate.test_note}</Paragraph>}</div>,
    }))} />}
    {pageControl('candidates')}
  </div>

  const agentReference = <div className="agent-reference-layout">
    <Card className="workbench-card agent-reference-nav" title="文档导航" size="small">
      <Menu mode="inline" selectedKeys={[selectedDocumentId]} items={agentDocuments.map((document) => ({ key: document.id, icon: document.kind === 'skill' ? <BookOutlined /> : <CodeOutlined />, label: document.title }))} onClick={({ key }) => setSelectedDocumentId(key)} />
    </Card>
    <Card className="workbench-card agent-reference-content" title={selectedDocument?.title || 'Agent 文档'} extra={selectedDocument && <Tag color={selectedDocument.kind === 'skill' ? 'blue' : 'purple'}>{selectedDocument.kind === 'skill' ? 'Skill' : '提示词'}</Tag>}>
      {agentDocumentsLoading ? <div className="agent-reference-loading"><Spin description="正在读取 Agent 文档…" /></div> : agentDocumentsError ? <Alert type="error" showIcon title="文档读取失败" description={agentDocumentsError} action={<Button size="small" onClick={() => void loadAgentDocuments()}>重试</Button>} /> : selectedDocument ? <pre className="agent-document-content">{selectedDocument.content}</pre> : <Empty description="暂无可展示的 Agent 文档" />}
    </Card>
  </div>

  const agentTabs: TabsProps['items'] = [
    { key: 'workspace', label: <span className="tab-label"><ApiOutlined />迭代工作台</span>, children: agentWorkbench },
    { key: 'reference', label: <span className="tab-label"><BookOutlined />Skills 与提示词</span>, children: agentReference },
  ]

  const agentWorkspace = <section className="workspace-card agent-workspace"><Tabs activeKey={agentTab} onChange={setAgentTab} items={agentTabs} /></section>

  const visibleEncodingCandidates = encodingCandidates.filter((candidate) => candidate.status !== 'archived')
  const selectedEncodingDocument = encodingDocuments.find((document) => document.id === selectedEncodingDocumentId)
  const encodingWorkbench = workspace === 'encoding' && <div className="agent-workbench">
    {visibleEncodingCandidates.some((candidate) => candidate.next_directions?.length) && <Card size="small" className="workbench-card" title="下一轮 AI 思考方向"><Space orientation="vertical" size="small">{visibleEncodingCandidates.filter((candidate) => candidate.next_directions?.length).map((candidate) => <div key={candidate.id}><Text strong>{candidate.base_payload_name}</Text>{iterationDirections(candidate.used_direction_ids, candidate.next_directions)}</div>)}</Space></Card>}
    <div className="agent-grid">
      <Card className="workbench-card" title={<Space><CodeOutlined />编码绕过迭代任务</Space>}>
        <Form layout="vertical">
          <Form.Item label="每条生成数量"><Space><InputNumber min={1} max={20} value={encodingCandidateCount} onChange={(value) => setEncodingCandidateCount(value ?? 5)} disabled={encodingGenerating} /><Text type="secondary">个候选</Text></Space></Form.Item>
          <div className="pool-heading"><Text strong>待迭代池</Text><Tag color="blue">{encodingPendingPool.length} 条</Tag></div>
          {renderPoolItems(encodingPendingPool)}
        </Form>
      </Card>
      <Card className="workbench-card" title="进行中任务">
        {encodingStartedPool.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无进行中任务" /> : <div className="pool-started-list">{encodingStartedPool.map((item) => <div className="pool-started-item" key={item.id}><Text strong>{item.snapshot.name}</Text><div><Tag color={item.task_status === 'completed' ? 'green' : item.task_status === 'failed' ? 'red' : 'blue'}>{item.task_status || 'queued'}</Tag><Text type="secondary">任务 ID：{item.task_id}</Text></div></div>)}</div>}
        {activeEncodingTask && <div className="task-status"><Tag color={activeEncodingTask.status === 'completed' ? 'green' : activeEncodingTask.status === 'failed' ? 'red' : 'blue'}>{activeEncodingTask.status}</Tag><Paragraph>当前任务：{activeEncodingTask.id}</Paragraph>{activeEncodingTask.status === 'failed' && <Alert type="error" title={activeEncodingTask.error_message || '编码生成失败'} />}</div>}
      </Card>
    </div>
    <div className="queue-heading"><Title level={5}>待测试队列</Title><Tag color="blue">{visibleEncodingCandidates.length} 条</Tag></div>
    {visibleEncodingCandidates.length === 0 ? <Card className="empty-card" variant="borderless"><Empty description="暂无编码候选" /></Card> : <Collapse className="candidate-accordion" accordion bordered={false} activeKey={expandedEncodingCandidate ? [expandedEncodingCandidate] : []} onChange={(key) => setExpandedEncodingCandidate(Array.isArray(key) ? key[0] || null : key || null)} items={visibleEncodingCandidates.map((candidate) => ({
      key: candidate.id,
      label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong>{candidate.base_payload_name}</Text><div className="candidate-card-meta"><Tag color="blue">{candidate.base_target}</Tag><Tag color="geekblue">{candidate.delivery}</Tag>{candidate.origin === 'semantic_boundary_migration' && <Tag color="orange">历史迁移</Tag>}{candidate.rule_labels.map((label) => <Tag key={label}>{label}</Tag>)}{statusTag(candidate.status)}</div></div><div className="candidate-card-actions" onClick={(event) => event.stopPropagation()}><Popconfirm title="删除该编码候选？" description="删除后无法恢复，且不会影响基础 Payload。" onConfirm={() => void deleteEncodingCandidate(candidate)}><Button danger type="link" size="small">删除</Button></Popconfirm></div></div>,
      children: <div className="candidate-detail">{candidatePayloadBlock('编码后 Payload', candidate.content)}{candidate.origin === 'semantic_boundary_migration' && <Alert type="warning" showIcon title="历史语义边界迁移" description={candidate.migration_note || '该候选来自旧版语义队列，未按新版编码重放器生成，请人工复核其解释前提。'} />}<div className="encoding-path"><Text strong>编码链：</Text><span>{candidate.encoding_chain.map((step) => `${encodingTypeLabels[step.type] || step.type}（${encodingModeLabel(step.mode)}）`).join(' → ')}</span></div><div className="encoding-path"><Text strong>预期解码路径：</Text><span>{candidate.decode_path.map((step) => encodingTypeLabels[step] || step).join(' → ')}</span></div>{encodingPrerequisites(candidate.encoding_chain) && <Paragraph type="secondary">{encodingPrerequisites(candidate.encoding_chain)}</Paragraph>}<Paragraph type="secondary">{candidate.explanation}</Paragraph>{candidate.status === 'pending_test' && <div className="candidate-actions"><Input placeholder="手工测试记录（可选）" value={encodingTestNotes[candidate.id] || ''} onClick={(event) => event.stopPropagation()} onChange={(event) => setEncodingTestNotes((current) => ({ ...current, [candidate.id]: event.target.value }))} /><Space><Button size="small" type="primary" onClick={() => void updateEncodingCandidate(candidate, 'test_success')}>标记测试成功</Button><Button size="small" danger onClick={() => void updateEncodingCandidate(candidate, 'test_failed')}>标记测试失败</Button><Button size="small" onClick={() => void updateEncodingCandidate(candidate, 'rejected')}>拒绝</Button></Space></div>}{archiveCandidateControls(candidate, 'encoding')}{candidate.test_note && <Paragraph type="secondary">测试记录：{candidate.test_note}</Paragraph>}</div>,
    }))} />}
    {pageControl('encodingCandidates')}
  </div>

  const encodingReference = <div className="agent-reference-layout">
    <Card className="workbench-card agent-reference-nav" title="文档导航" size="small">
      <Menu mode="inline" selectedKeys={[selectedEncodingDocumentId]} items={encodingDocuments.map((document) => ({ key: document.id, icon: document.kind === 'skill' ? <BookOutlined /> : <CodeOutlined />, label: document.title }))} onClick={({ key }) => setSelectedEncodingDocumentId(key)} />
    </Card>
    <Card className="workbench-card agent-reference-content" title={selectedEncodingDocument?.title || '编码 Agent 文档'} extra={selectedEncodingDocument && <Tag color={selectedEncodingDocument.kind === 'skill' ? 'blue' : 'purple'}>{selectedEncodingDocument.kind === 'skill' ? 'Skill' : '提示词'}</Tag>}>
      {encodingDocumentsLoading ? <div className="agent-reference-loading"><Spin description="正在读取编码 Agent 文档…" /></div> : encodingDocumentsError ? <Alert type="error" showIcon title="文档读取失败" description={encodingDocumentsError} action={<Button size="small" onClick={() => void loadEncodingDocuments()}>重试</Button>} /> : selectedEncodingDocument ? <pre className="agent-document-content">{selectedEncodingDocument.content}</pre> : <Empty description="暂无可展示的编码 Agent 文档" />}
    </Card>
  </div>

  const encodingAgentTabs: TabsProps['items'] = [
    { key: 'workspace', label: <span className="tab-label"><CodeOutlined />编码迭代工作台</span>, children: encodingWorkbench },
    { key: 'reference', label: <span className="tab-label"><BookOutlined />Skills 与提示词</span>, children: encodingReference },
  ]

  const encodingWorkspace = <section className="workspace-card agent-workspace"><Tabs activeKey={encodingAgentTab} onChange={setEncodingAgentTab} items={encodingAgentTabs} /></section>

  const visibleCrossCandidates = crossCandidates
  const crossWorkspace = workspace === 'cross' && <section className="workspace-card agent-workspace"><div className="agent-workbench">
    <div className="agent-grid">
      <Card className="workbench-card" title={<Space><ApartmentOutlined />正向交叉迭代任务</Space>}>
        <Form layout="vertical">
          <Form.Item label="待交叉来源" required>
            <Select
              value={selectedCrossSourceId}
              placeholder="选择已归档的语义迭代 Payload"
              options={crossSources.map((source) => ({ value: source.id, label: `${source.name} · ${source.target}` }))}
              onChange={setSelectedCrossSourceId}
            />
          </Form.Item>
          {selectedCrossSource ? <div className="agent-base-summary"><Text strong>{selectedCrossSource.name}</Text><div className="agent-base-tags"><Tag color={vulnerabilityDefinitions[selectedCrossSource.vulnerability].tagColor}>{vulnerabilityDefinitions[selectedCrossSource.vulnerability].label}</Tag><Tag>{selectedCrossSource.target}</Tag><Tag color="geekblue">{selectedCrossSource.delivery}</Tag>{selectedCrossSource.rule_labels.map((label) => <Tag key={label}>{label}</Tag>)}</div><Paragraph code>{selectedCrossSource.content}</Paragraph></div> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="语义候选归档后会自动进入待交叉库" />}
          <Form.Item label="生成数量"><Space><InputNumber min={1} max={20} value={crossCandidateCount} onChange={(value) => setCrossCandidateCount(value ?? 5)} disabled={crossGenerating} /><Text type="secondary">个候选</Text></Space></Form.Item>
          <Button type="primary" icon={<ApartmentOutlined />} loading={crossGenerating} disabled={!selectedCrossSourceId || !selectedCrossSource || selectedCrossSource.available_chain_count < crossCandidateCount} onClick={() => void startCrossGeneration()}>生成正向交叉候选</Button>
        </Form>
      </Card>
      <Card className="workbench-card" title="任务状态">
        {activeCrossTask ? <div className="task-status"><Tag color={activeCrossTask.status === 'completed' ? 'green' : 'red'}>{activeCrossTask.status}</Tag><Paragraph>任务 ID：{activeCrossTask.id}</Paragraph>{activeCrossTask.status === 'failed' && <Alert type="error" title={activeCrossTask.error_message || '正向交叉生成失败'} />}{activeCrossTask.status === 'completed' && <Text type="secondary">已确定性重放 {activeCrossTask.candidate_count} 条未使用编码链。</Text>}</div> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="尚未创建正向交叉任务" />}
        {selectedCrossSource && <div className="cross-capacity"><Text type="secondary">当前来源可用未重复编码链：</Text><Tag color={selectedCrossSource.available_chain_count >= crossCandidateCount ? 'green' : 'red'}>{selectedCrossSource.available_chain_count} 条</Tag></div>}
      </Card>
    </div>
    <div className="queue-heading"><Title level={5}>待测试队列</Title><Tag color="blue">{visibleCrossCandidates.length} 条</Tag></div>
    {visibleCrossCandidates.length === 0 ? <Card className="empty-card" variant="borderless"><Empty description="暂无正向交叉候选" /></Card> : <Collapse className="candidate-accordion" accordion bordered={false} activeKey={expandedCrossCandidate ? [expandedCrossCandidate] : []} onChange={(key) => setExpandedCrossCandidate(Array.isArray(key) ? key[0] || null : key || null)} items={visibleCrossCandidates.map((candidate) => ({
      key: candidate.id,
      label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong>{candidate.source_name}</Text><div className="candidate-card-meta"><Tag color="blue">{candidate.source_target}</Tag><Tag color="geekblue">{candidate.source_delivery}</Tag>{candidate.semantic_rule_labels.map((label) => <Tag key={`semantic-${label}`}>{label}</Tag>)}{candidate.rule_labels.map((label) => <Tag color="purple" key={`encoding-${label}`}>{label}</Tag>)}{statusTag(candidate.status)}</div></div><div className="candidate-card-actions" onClick={(event) => event.stopPropagation()}><Popconfirm title="删除该正向交叉候选？" description="候选会删除，但该编码链会保留为历史记录，不会重复生成。" onConfirm={() => void deleteCrossCandidate(candidate)}><Button danger type="link" size="small">删除</Button></Popconfirm></div></div>,
      children: <div className="candidate-detail"><div className="candidate-payload-block"><div className="candidate-content-heading"><Text type="secondary">语义来源 Payload</Text></div><pre className="candidate-content">{candidate.semantic_content}</pre></div>{candidatePayloadBlock('编码后 Payload', candidate.content)}<div className="encoding-path"><Text strong>编码链：</Text><span>{candidate.encoding_chain.map((step) => `${encodingTypeLabels[step.type] || step.type}（${step.mode === 'full' ? '全量' : '特殊字符'}）`).join(' → ')}</span></div><div className="encoding-path"><Text strong>预期解码路径：</Text><span>{candidate.decode_path.map((step) => encodingTypeLabels[step] || step).join(' → ')}</span></div>{candidate.status === 'pending_test' && <div className="candidate-actions"><Input placeholder="手工测试记录（可选）" value={crossTestNotes[candidate.id] || ''} onClick={(event) => event.stopPropagation()} onChange={(event) => setCrossTestNotes((current) => ({ ...current, [candidate.id]: event.target.value }))} /><Space><Button size="small" type="primary" onClick={() => void updateCrossCandidate(candidate, 'test_success')}>标记测试成功</Button><Button size="small" danger onClick={() => void updateCrossCandidate(candidate, 'test_failed')}>标记测试失败</Button><Button size="small" onClick={() => void updateCrossCandidate(candidate, 'rejected')}>拒绝</Button></Space></div>}{candidate.status === 'test_success' && <Button size="small" onClick={() => void updateCrossCandidate(candidate, 'pending_test')}>取消成功标记</Button>}{candidate.status === 'test_failed' && <Button size="small" onClick={() => void updateCrossCandidate(candidate, 'pending_test')}>取消失败标记</Button>}{candidate.test_note && <Paragraph type="secondary">测试记录：{candidate.test_note}</Paragraph>}</div>,
    }))} />}
    {pageControl('crossCandidates')}
  </div></section>

  const filteredSamples = successSamples.filter((sample) => (
    (!sampleAgentFilter || sample.agent === sampleAgentFilter)
    && (!sampleVulnerabilityFilter || sample.vulnerability === sampleVulnerabilityFilter)
    && (!sampleTargetFilter || sample.target === sampleTargetFilter)
    && (!sampleDeliveryFilter || sample.delivery === sampleDeliveryFilter)
  ))
  const distinctSampleValues = (key: keyof Pick<SuccessSample, 'target' | 'delivery'>) => Array.from(new Set(successSamples.map((sample) => sample[key]))).map((value) => ({ value, label: value }))
  const sampleColumns = [
    { title: '名称', dataIndex: 'name', key: 'name', ellipsis: true },
    { title: '来源', dataIndex: 'agent', key: 'agent', width: 110, render: (agent: SuccessSample['agent']) => <Tag color={agent === 'cross' ? 'purple' : agent === 'encoding' ? 'cyan' : 'blue'}>{sampleAgentLabels[agent]}</Tag> },
    { title: '漏洞', dataIndex: 'vulnerability', key: 'vulnerability', width: 105, render: (vulnerability: VulnerabilityKey) => vulnerabilityDefinitions[vulnerability].label },
    { title: '靶场', dataIndex: 'target', key: 'target', width: 90 },
    { title: '投递方式', dataIndex: 'delivery', key: 'delivery', width: 150, ellipsis: true },
    { title: '报告', key: 'report', width: 120, render: (_: unknown, sample: SuccessSample) => <Button type="link" size="small" icon={<FileTextOutlined />} onClick={() => void openSampleReport(sample)}>{reports.some((report) => report.success_sample_id === sample.id) ? '打开报告' : '撰写报告'}</Button> },
  ]
  const successSamplesWorkspace = workspace === 'samples' && <section className="workspace-card payload-workspace"><div className="samples-workspace">
    <div className="panel-heading"><Space><TrophyOutlined /><Title level={5}>成功样例</Title><Tag color="green">{filteredSamples.length} 条</Tag></Space><Text type="secondary">只读等待区，用于追溯各 Agent 已确认成功的结果。</Text></div>
    <Card className="workbench-card" size="small" title="筛选">
      <div className="sample-filter-grid"><Select allowClear placeholder="来源 Agent" value={sampleAgentFilter} options={Object.entries(sampleAgentLabels).map(([value, label]) => ({ value, label }))} onChange={(value) => { setSampleAgentFilter(value); setPage((current) => ({ ...current, samples: 1 })) }} /><Select allowClear placeholder="漏洞类型" value={sampleVulnerabilityFilter} options={vulnerabilityKeys.map((value) => ({ value, label: vulnerabilityDefinitions[value].label }))} onChange={(value) => { setSampleVulnerabilityFilter(value); setPage((current) => ({ ...current, samples: 1 })) }} /><Select allowClear placeholder="靶场" value={sampleTargetFilter} options={distinctSampleValues('target')} onChange={(value) => { setSampleTargetFilter(value); setPage((current) => ({ ...current, samples: 1 })) }} /><Select allowClear placeholder="投递方式" value={sampleDeliveryFilter} options={distinctSampleValues('delivery')} onChange={(value) => { setSampleDeliveryFilter(value); setPage((current) => ({ ...current, samples: 1 })) }} /></div>
    </Card>
    {filteredSamples.length === 0 ? <Card className="empty-card" variant="borderless"><Empty description="暂无成功样例" /></Card> : <><Card className="workbench-card payload-table-card" title="样例索引" size="small"><Table<SuccessSample> className="payload-table" rowKey="id" size="small" pagination={false} columns={sampleColumns} dataSource={filteredSamples} /></Card>{pageControl('samples')}<div className="accordion-section-title">样例详情</div><Collapse className="candidate-accordion" accordion bordered={false} activeKey={expandedSample ? [expandedSample] : []} onChange={(key) => setExpandedSample(Array.isArray(key) ? key[0] || null : key || null)} items={filteredSamples.map((sample) => ({ key: sample.id, label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong>{sample.name}</Text><div className="candidate-card-meta"><Tag color={sample.agent === 'cross' ? 'purple' : sample.agent === 'encoding' ? 'cyan' : 'blue'}>{sampleAgentLabels[sample.agent]}</Tag><Tag>{vulnerabilityDefinitions[sample.vulnerability].label}</Tag><Tag>{sample.target}</Tag><Tag>{sample.difficulty}</Tag>{sample.archived_payload_id && <Tag color="green">已归档</Tag>}</div></div></div>, children: <div className="candidate-detail"><div className="sample-detail-actions"><Space><Button type="primary" size="small" icon={<FileTextOutlined />} onClick={() => void openSampleReport(sample)}>{reports.some((report) => report.success_sample_id === sample.id) ? '打开报告' : '发送到报告撰写'}</Button><Popconfirm title="从成功样例库删除该条目？" description="只移除样例展示，不会删除来源候选、归档 Payload 或待交叉来源。" onConfirm={() => void deleteSuccessSample(sample)}><Button danger size="small">删除样例</Button></Popconfirm></Space></div><Text type="secondary">成功 Payload</Text><pre className="candidate-content">{sample.content}</pre><Paragraph type="secondary">投递方式：{sample.delivery}</Paragraph>{sample.test_note && <Paragraph type="secondary">测试记录：{sample.test_note}</Paragraph>}<Text type="secondary">来源链路</Text><pre className="candidate-content">{JSON.stringify(sample.provenance, null, 2)}</pre></div> }))} /></>}
  </div></section>

  const reportSaveTag = reportSaveState === 'saved'
    ? <Tag color="green">已保存</Tag>
    : reportSaveState === 'saving'
    ? <Tag color="blue">保存中</Tag>
    : reportSaveState === 'dirty'
    ? <Tag color="orange">未保存</Tag>
    : <Tag color="red">保存失败</Tag>
  const orderedReportImages = workspace === 'reports' && reportDraft ? [...reportDraft.images].sort((left, right) => left.sort_order - right.sort_order) : []
  const reportBasicItems = workspace === 'reports' && reportDraft ? [
    { key: 'sample', label: '成功样例', children: reportDraft.sample_name },
    { key: 'agent', label: '来源 Agent', children: <Tag color={reportDraft.source_agent === 'cross' ? 'purple' : reportDraft.source_agent === 'encoding' ? 'cyan' : 'blue'}>{sampleAgentLabels[reportDraft.source_agent]}</Tag> },
    { key: 'vulnerability', label: '漏洞类型', children: vulnerabilityDefinitions[reportDraft.vulnerability].label },
    { key: 'category', label: '分类', children: reportDraft.category },
    { key: 'target', label: '靶场', children: reportDraft.target },
    { key: 'delivery', label: '投递方式', children: reportDraft.delivery },
  ] : []
  const reportEditor = workspace === 'reports' && reportDraft ? <div className="report-editor">
    <Card size="small" className="report-section" title="Payload 基本信息" extra={reportDraft.source_status === 'active' ? <Tag color="green">来源有效</Tag> : <Tag color="red">来源已失效</Tag>}>
      <Descriptions size="small" column={{ xs: 1, sm: 2, lg: 3 }} items={reportBasicItems} />
      <Form layout="vertical">
        <Form.Item label="Payload" required><Input.TextArea rows={8} maxLength={10000} showCount value={reportDraft.payload_content} onChange={(event) => updateReportField('payload_content', event.target.value)} /></Form.Item>
      </Form>
      {reportDraft.sample_test_note && <Paragraph type="secondary">样例测试记录：{reportDraft.sample_test_note}</Paragraph>}
    </Card>
    <Card size="small" className="report-section" title="报告内容">
      <Form layout="vertical">
        <Form.Item label="报告标题" required><Input value={reportDraft.title} maxLength={200} showCount onChange={(event) => updateReportField('title', event.target.value)} /></Form.Item>
        <div className="report-form-grid">
          <Form.Item label="验证环境"><Input.TextArea autoSize={{ minRows: 3, maxRows: 7 }} maxLength={2000} showCount value={reportDraft.verification_environment} onChange={(event) => updateReportField('verification_environment', event.target.value)} /></Form.Item>
          <Form.Item label="前置条件"><Input.TextArea autoSize={{ minRows: 3, maxRows: 7 }} maxLength={5000} showCount value={reportDraft.prerequisites} onChange={(event) => updateReportField('prerequisites', event.target.value)} /></Form.Item>
        </div>
        <Form.Item label="复现 / 验证步骤"><Input.TextArea autoSize={{ minRows: 5, maxRows: 12 }} maxLength={10000} showCount value={reportDraft.verification_steps} onChange={(event) => updateReportField('verification_steps', event.target.value)} /></Form.Item>
        <Form.Item label="实际验证结果"><Input.TextArea autoSize={{ minRows: 4, maxRows: 10 }} maxLength={10000} showCount value={reportDraft.actual_result} onChange={(event) => updateReportField('actual_result', event.target.value)} /></Form.Item>
      </Form>
    </Card>
    <Card size="small" className="report-section" title="验证图片" extra={<Tag>{orderedReportImages.length} / 10</Tag>}>
      <div className="report-evidence-actions">
        <Upload multiple accept="image/png,image/jpeg,image/webp" showUploadList={false} disabled={reportUploading || orderedReportImages.length >= 10} beforeUpload={(file) => { void uploadReportImages([file]); return false }}>
          <Button icon={<UploadOutlined />} disabled={reportUploading || orderedReportImages.length >= 10}>上传图片</Button>
        </Upload>
        <Text type="secondary">PNG、JPEG、WebP，单张不超过 10MB</Text>
      </div>
      <div
        className={`report-paste-box ${reportUploading || orderedReportImages.length >= 10 ? 'report-paste-box-disabled' : ''}`}
        role="textbox"
        aria-label="图片粘贴输入框"
        aria-disabled={reportUploading || orderedReportImages.length >= 10}
        tabIndex={reportUploading || orderedReportImages.length >= 10 ? -1 : 0}
        onPaste={reportUploading || orderedReportImages.length >= 10 ? undefined : pasteReportImages}
      >
        <CopyOutlined />
        <div><Text strong>图片粘贴输入框</Text><Text type="secondary">点击此处后按 Ctrl+V，直接粘贴剪贴板中的截图</Text></div>
      </div>
      {reportUploading && <div className="report-uploading"><Spin size="small" /><Text type="secondary">正在保存验证图片…</Text></div>}
      {orderedReportImages.length > 0 && <div className="report-image-grid">{orderedReportImages.map((image, index) => <div className="report-image-item" key={image.id}>
        <img src={image.content_url} alt={image.caption || image.original_name} />
        <Input placeholder="图片说明" value={image.caption} maxLength={500} onChange={(event) => updateReportImageCaption(image.id, event.target.value)} onBlur={(event) => void saveReportImage(image, { caption: event.target.value })} />
        <div className="report-image-meta"><Text type="secondary">{image.original_name} · {(image.size_bytes / 1024).toFixed(1)} KB</Text><Space size={4}><Button size="small" icon={<ArrowUpOutlined />} disabled={index === 0} aria-label="上移图片" onClick={() => void moveReportImage(image, -1)} /><Button size="small" icon={<ArrowDownOutlined />} disabled={index === orderedReportImages.length - 1} aria-label="下移图片" onClick={() => void moveReportImage(image, 1)} /><Popconfirm title="删除这张验证图片？" onConfirm={() => void deleteReportImage(image)}><Button danger size="small">删除</Button></Popconfirm></Space></div>
      </div>)}</div>}
    </Card>
    <Card size="small" className="report-section" title="结论与记录">
      <Form layout="vertical">
        <Form.Item label="验证结论"><Input.TextArea autoSize={{ minRows: 3, maxRows: 8 }} maxLength={5000} showCount value={reportDraft.conclusion} onChange={(event) => updateReportField('conclusion', event.target.value)} /></Form.Item>
        <div className="report-form-grid report-form-grid-compact">
          <Form.Item label="测试人员"><Input maxLength={128} value={reportDraft.tester} onChange={(event) => updateReportField('tester', event.target.value)} /></Form.Item>
          <Form.Item label="验证日期"><Input type="date" value={reportDraft.verification_date} onChange={(event) => updateReportField('verification_date', event.target.value)} /></Form.Item>
        </div>
        <Form.Item label="备注"><Input.TextArea autoSize={{ minRows: 3, maxRows: 8 }} maxLength={5000} showCount value={reportDraft.notes} onChange={(event) => updateReportField('notes', event.target.value)} /></Form.Item>
      </Form>
    </Card>
  </div> : <Empty description="请选择或创建一份报告" />
  const reportPreview = workspace === 'reports' && reportDraft ? <article className="report-preview">
    <header><Title level={2}>{reportDraft.title || '未命名验证报告'}</Title><Space wrap><Tag>{vulnerabilityDefinitions[reportDraft.vulnerability].label}</Tag><Tag>{reportDraft.target}</Tag><Tag color={reportDraft.source_status === 'active' ? 'green' : 'red'}>{reportDraft.source_status === 'active' ? '来源有效' : '来源已失效'}</Tag></Space></header>
    <Divider />
    <Title level={4}>Payload 基本信息</Title><Descriptions bordered size="small" column={{ xs: 1, sm: 2 }} items={reportBasicItems} />
    <pre className="candidate-content report-preview-payload">{reportDraft.payload_content}</pre>
    <Title level={4}>验证环境</Title><Paragraph>{reportDraft.verification_environment || '待补充'}</Paragraph>
    <Title level={4}>前置条件</Title><Paragraph>{reportDraft.prerequisites || '待补充'}</Paragraph>
    <Title level={4}>复现 / 验证步骤</Title><Paragraph className="report-preserve-lines">{reportDraft.verification_steps || '待补充'}</Paragraph>
    <Title level={4}>实际验证结果</Title><Paragraph className="report-preserve-lines">{reportDraft.actual_result || '待补充'}</Paragraph>
    <Title level={4}>验证图片</Title>{orderedReportImages.length ? <div className="report-preview-images">{orderedReportImages.map((image) => <figure key={image.id}><img src={image.content_url} alt={image.caption || image.original_name} /><figcaption>{image.caption || image.original_name}</figcaption></figure>)}</div> : <Paragraph type="secondary">尚未加入验证图片</Paragraph>}
    <Title level={4}>验证结论</Title><Paragraph className="report-preserve-lines">{reportDraft.conclusion || '待补充'}</Paragraph>
    <div className="report-preview-signoff"><span>测试人员：{reportDraft.tester || '待补充'}</span><span>验证日期：{reportDraft.verification_date || '待补充'}</span></div>
    {reportDraft.notes && <><Title level={4}>备注</Title><Paragraph className="report-preserve-lines">{reportDraft.notes}</Paragraph></>}
  </article> : <Empty description="请选择或创建一份报告" />
  const reportsWorkspace = workspace === 'reports' && <section className="workspace-card report-workspace">
    <div className="panel-heading"><div><Space><FileTextOutlined /><Title level={5}>报告撰写</Title><Tag color="blue">{reports.length} 份</Tag></Space><Text type="secondary">从成功样例创建独立的模板化验证报告。</Text></div></div>
    <div className="report-layout">
      <Card className="report-list" size="small" title="报告列表">
        {reports.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无报告，请从成功样例发送" /> : <div className="report-list-items">{reports.map((report) => <button type="button" key={report.id} className={`report-list-item ${selectedReportId === report.id ? 'report-list-item-active' : ''}`} onClick={() => void selectReport(report)}><strong>{report.title}</strong><span><Tag color={vulnerabilityDefinitions[report.vulnerability].tagColor}>{vulnerabilityDefinitions[report.vulnerability].label}</Tag>{report.source_status === 'active' ? <Tag color="green">来源有效</Tag> : <Tag color="red">来源失效</Tag>}</span><small>{report.updated_at}</small></button>)}</div>}
      </Card>
      <div className="report-main">
        {reportDraft && <div className="report-toolbar"><div><Title level={5}>{reportDraft.title}</Title><Text type="secondary">更新于 {reportDraft.updated_at}</Text></div><Space wrap>{reportSaveTag}<Button icon={<SaveOutlined />} type="primary" loading={reportSaveState === 'saving'} onClick={() => void saveReport(reportDraft, true)}>保存</Button><Popconfirm title="删除这份报告？" description="报告和验证图片会删除，来源成功样例不受影响。" onConfirm={() => void deleteReport(reportDraft)}><Button danger>删除报告</Button></Popconfirm></Space></div>}
        <Tabs activeKey={reportTab} onChange={setReportTab} items={[{ key: 'edit', label: '模板填写', children: reportEditor }, { key: 'preview', label: '报告预览', children: reportPreview }]} />
      </div>
    </div>
  </section>

  const [directWafTarget, setDirectWafTarget] = useState('tencent-waf')
  const [directWafContent, setDirectWafContent] = useState('')
  const [directWafName, setDirectWafName] = useState('')
  const [directWafSending, setDirectWafSending] = useState(false)

  const sendDirectWafTest = async () => {
    if (!directWafContent.trim()) return
    setDirectWafSending(true)
    try {
      await api<WafTestRun>('/waf-test-runs/direct', {
        method: 'POST',
        body: JSON.stringify({ target: directWafTarget, content: directWafContent.trim(), name: directWafName.trim() || '直接测试' }),
      })
      messageApi.success('Payload 已发送到腾讯云 WAF')
      await loadWafData()
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '发送失败')
    } finally {
      setDirectWafSending(false)
    }
  }

  const wafSceneUsesLegacyApi = Boolean(
    wafScene && (wafScene.dvwa === undefined || wafScene.direct_targets === undefined),
  )
  const staleWafBackendAlert = <Alert
    type="warning"
    showIcon
    title="后端版本未更新"
    description="当前 FastAPI 仍在返回旧版测试场接口，请重启 127.0.0.1:8000 后刷新页面。"
  />

  const wafWorkspace = workspace === 'waf' && <section className="workspace-card payload-workspace">
    <Tabs defaultActiveKey="dvwa" items={[
      { key: 'dvwa', label: 'DVWA + 雷池 WAF', children: <div>
        <div className="panel-heading"><Space><SafetyCertificateOutlined /><Title level={5}>DVWA + 雷池 WAF 测试场</Title></Space><Text type="secondary">仅测试配置中的已授权 DVWA；结果不会自动改变候选状态。</Text></div>
        <Card className="workbench-card" title="场景状态" extra={<Button type="primary" loading={wafLoading} onClick={() => void preflightWaf()}>执行预检</Button>}>
          {wafSceneUsesLegacyApi ? staleWafBackendAlert : wafScene?.dvwa?.configured ? <Space wrap><Tag color="green">已配置</Tag><Text>{wafScene.dvwa.base_url}</Text><Tag color="blue">固定安全等级：Low</Tag><Text type="secondary">支持命令注入、SQL 注入、反射型 XSS</Text></Space> : <Alert type="error" showIcon title="测试场未配置" description={wafScene?.dvwa?.error || '正在读取配置'} />}
        </Card>
      </div> },
      { key: 'tencent', label: '腾讯云 WAF', children: wafSceneUsesLegacyApi ? staleWafBackendAlert : Object.keys(wafScene?.direct_targets || {}).length > 0 ? <div>
        <div className="panel-heading"><Space><SafetyCertificateOutlined /><Title level={5}>腾讯云 WAF 直接测试</Title></Space><Text type="secondary">直接 HTTP 请求 + 自定义 Host 头；200 = WAF 放行，403 = WAF 拦截。无需 DVWA 登录。</Text></div>
        <Card className="workbench-card" title="连接状态">
          {wafScene?.tencent_waf?.configured ? <Space wrap>
            <Tag color="green">已连接</Tag>
            <Tag color="blue">IP: {wafScene.tencent_waf.ip}</Tag>
            <Tag color="purple">Host: {wafScene.tencent_waf.host}</Tag>
            <Tag color={wafScene.tencent_waf.preflight_status === 200 ? 'green' : 'orange'}>预检: HTTP {wafScene.tencent_waf.preflight_status} ({wafScene.tencent_waf.preflight_result})</Tag>
          </Space> : <Alert type="error" showIcon title="未配置" description={wafScene?.tencent_waf?.error || '请在 config/.env 中设置 TENCENT_WAF_IP 和 TENCENT_WAF_HOST'} />}
        </Card>
        <Card className="workbench-card" title="直接发送 Payload">
          <Form layout="inline" style={{ marginBottom: 12 }}>
            <Form.Item label="Payload 名称"><Input placeholder="测试名称" value={directWafName} onChange={(e) => setDirectWafName(e.target.value)} style={{ width: 160 }} /></Form.Item>
          </Form>
          <Input.TextArea rows={3} placeholder="在此粘贴 Payload 内容（将放入 URL 路径中发送）" value={directWafContent} onChange={(e) => setDirectWafContent(e.target.value)} style={{ marginBottom: 12 }} />
          <Button type="primary" icon={<SafetyCertificateOutlined />} loading={directWafSending} disabled={!directWafContent.trim()} onClick={() => void sendDirectWafTest()}>发送到腾讯云 WAF</Button>
          <Text type="secondary" style={{ marginLeft: 12 }}>Payload 将被发送到 http://{wafScene?.tencent_waf?.ip || '...'}/&lt;payload&gt;  Host: {wafScene?.tencent_waf?.host || '...'}</Text>
        </Card>
      </div> : <Alert type="warning" showIcon title="未检测到直接 WAF 目标" description="后端 DIRECT_WAF_TARGETS 为空，请检查 waf_testing.py 中的注册表。" /> },
    ]} />
    <Card className="workbench-card" title="最近测试记录" extra={<Button size="small" onClick={() => void loadWafData()}>刷新</Button>} style={{ marginTop: 16 }}>
      {wafRuns.length === 0 ? <Empty description="暂无 WAF 测试记录" /> : <Table<WafTestRun> rowKey="id" size="small" pagination={{ pageSize: 8 }} dataSource={wafRuns} columns={[
        { title: '候选', dataIndex: 'base_name', key: 'name', ellipsis: true }, { title: '漏洞', dataIndex: 'vulnerability', key: 'vulnerability' }, { title: '状态', key: 'result', render: (_, run) => <Tag color={run.result === 'execution_confirmed' ? 'green' : run.result === 'waf_blocked' || run.result === 'waf_bypassed' ? 'red' : 'blue'}>{run.result || run.status}</Tag> }, { title: '证据', dataIndex: 'evidence', key: 'evidence', ellipsis: true }, { title: '时间', dataIndex: 'created_at', key: 'created_at', width: 190 },
      ]} />}
    </Card>
  </section>

  // ── curl 命令生成器 ──────────────────────────────────────────────
  const [curlPayload, setCurlPayload] = useState('')

  // RFC 3986 pchar 白名单编码，与 httpx 的路径编码行为一致
  // 允许: A-Z a-z 0-9 - . _ ~ ! $ & ' ( ) * + , ; = : @ /
  // 其余字符（含空格、?、#、{、}、%、[、]、^、`、|、<、>）全部编码
  const encodePayloadForUrl = (raw: string): string => {
    return raw
      .split('')
      .map((ch) => {
        if (/[A-Za-z0-9\-._~!$&'()*+,;=:@/]/.test(ch)) return ch
        const bytes = new TextEncoder().encode(ch)
        return Array.from(bytes).map((b) => '%' + b.toString(16).toUpperCase().padStart(2, '0')).join('')
      })
      .join('')
  }

  const ip = wafScene?.tencent_waf?.ip || '<IP>'
  const host = wafScene?.tencent_waf?.host || '<Host>'
  const encodedPayload = encodePayloadForUrl(curlPayload.replace(/^\/+/, ''))
  const curlCommand = curlPayload.trim()
    ? `curl "http://${ip}/${encodedPayload}" -H "host:${host}"`
    : ''

  const curlToolWorkspace = workspace === 'curl-tool' && <section className="workspace-card payload-workspace">
    <div className="panel-heading">
      <Space><ToolOutlined /><Title level={5}>curl 命令生成器</Title></Space>
      <Text type="secondary">输入原始 Payload，自动完成 URL 路径编码，输出可直接用于腾讯云 WAF 手动测试的 curl 命令。</Text>
    </div>
    <Card className="workbench-card" title="目标配置">
      {wafScene?.tencent_waf?.configured
        ? <Space wrap>
            <Tag color="green">已连接</Tag>
            <Tag color="blue">IP: {wafScene.tencent_waf.ip}</Tag>
            <Tag color="purple">Host: {wafScene.tencent_waf.host}</Tag>
          </Space>
        : <Alert type="warning" showIcon title="腾讯云 WAF 未配置" description="请先在 WAF 测试场中完成 TENCENT_WAF_IP 和 TENCENT_WAF_HOST 配置，或前往 WAF 测试场刷新连接状态。" />}
    </Card>
    <Card className="workbench-card" title="原始 Payload 输入">
      <Input.TextArea
        rows={4}
        placeholder={`;$\{PATH:0:1}bin$\{PATH:0:1}cut -d: -f1 /etc/./pass?d`}
        value={curlPayload}
        onChange={(e) => setCurlPayload(e.target.value)}
        style={{ fontFamily: 'monospace' }}
      />
      {curlPayload.trim() && <div style={{ marginTop: 12 }}>
        <Text type="secondary">URL 编码后路径：</Text>
        <pre style={{ background: '#f5f5f5', padding: '8px 12px', borderRadius: 4, marginTop: 4, wordBreak: 'break-all', whiteSpace: 'pre-wrap' }}>
          {`/${encodedPayload}`}
        </pre>
      </div>}
    </Card>
    {curlCommand && <Card
      className="workbench-card"
      title="生成的 curl 命令"
      extra={
        <Button
          size="small"
          icon={<CopyOutlined />}
          onClick={() => void copyCandidatePayload(curlCommand)}
        >
          复制命令
        </Button>
      }
    >
      <pre style={{ background: '#1a1a2e', color: '#e0e0e0', padding: '12px 16px', borderRadius: 6, overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
        {curlCommand}
      </pre>
      <Alert
        style={{ marginTop: 12 }}
        type="info"
        showIcon
        description={
          <span>
            单引号包裹 URL，防止 shell 展开 <code>$&#123;&#125;</code>；特殊字符（空格、<code>?</code>、<code>&#123;&#125;</code> 等）已 URL 编码，与程序内部 httpx 请求行为一致。
          </span>
        }
      />
    </Card>}
    <Card className="workbench-card" title="编码对照说明" size="small">
      <Table
        size="small"
        pagination={false}
        dataSource={[
          { char: '空格', raw: ' ', encoded: '%20' },
          { char: '问号 ?', raw: '?', encoded: '%3F' },
          { char: '花括号 { }', raw: '{ }', encoded: '%7B %7D' },
          { char: '井号 #', raw: '#', encoded: '%23' },
          { char: '百分号 %', raw: '%', encoded: '%25' },
          { char: '方括号 [ ]', raw: '[ ]', encoded: '%5B %5D' },
        ]}
        columns={[
          { title: '字符', dataIndex: 'char', key: 'char', width: 140 },
          { title: '原始', dataIndex: 'raw', key: 'raw', width: 80, render: (v: string) => <code>{v}</code> },
          { title: '编码后', dataIndex: 'encoded', key: 'encoded', render: (v: string) => <code>{v}</code> },
        ]}
      />
    </Card>
  </section>

  const workspaceLabels: Record<WorkspaceKey, string> = {
    dashboard: '项目仪表盘',
    library: 'Payload 库',
    agent: '语义迭代 Agent',
    encoding: '编码绕过 Agent',
    cross: '正向交叉迭代',
    waf: 'WAF 测试场',
    samples: '成功样例',
    reports: '报告撰写',
    'curl-tool': 'curl 命令生成器',
  }

  const workspaceContent = workspace === 'dashboard'
    ? dashboardWorkspace
    : workspace === 'library'
    ? <section className="workspace-card payload-workspace"><Tabs activeKey={libraryTab} onChange={setLibraryTab} items={libraryTabs} /></section>
    : workspace === 'agent' ? agentWorkspace : workspace === 'encoding' ? encodingWorkspace : workspace === 'cross' ? crossWorkspace : workspace === 'waf' ? wafWorkspace : workspace === 'curl-tool' ? curlToolWorkspace : workspace === 'reports' ? reportsWorkspace : successSamplesWorkspace

  return <ConfigProvider theme={{ token: { colorPrimary: '#1677ff', colorBgLayout: '#f5f7fa', borderRadius: 6, fontFamily: "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif" } }}>
    {messageContext}
    <Layout className="app-shell">
      <Sider className="app-sider" width={224} collapsedWidth={64} collapsed={collapsed} trigger={null} theme="light"><div className={`brand ${collapsed ? 'brand-collapsed' : ''}`}><span className="brand-mark"><SafetyCertificateOutlined /></span>{!collapsed && <span className="brand-name">WAFByPasser 工作台</span>}</div><Menu className="app-menu" mode="inline" selectedKeys={[workspace]} items={navigationItems} onClick={({ key }) => setWorkspace(key as WorkspaceKey)} /></Sider>
      <Layout className="main-layout"><Header className="top-header"><Button className="collapse-button" type="text" icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />} onClick={() => setCollapsed((value) => !value)} /><div className="header-divider" /><div className="header-object"><Breadcrumb className="header-breadcrumb" items={[{ title: '工作台' }, { title: workspaceLabels[workspace] }]} /><Text className="header-object-title">{workspaceLabels[workspace]}</Text></div><div className="header-actions"><Tag color="success">{dashboardSummary?.payload_count ?? totals.payloads ?? payloads.length} 条已录入</Tag>{workspace === 'library' && <Button size="small" type="primary" icon={<FileAddOutlined />} onClick={() => setLibraryTab('source')}>添加 Payload</Button>}</div></Header>
        <Content className="page-content">{apiError && <Alert className="api-error" type="warning" showIcon title="数据加载延迟" description={apiError} action={<Button size="small" onClick={() => void loadData(false)}>重试</Button>} />}{loading ? <div className="page-spinner"><Spin description="正在读取本地数据…" /></div> : workspaceContent}</Content>
      </Layout>
    </Layout>
  </ConfigProvider>
}
