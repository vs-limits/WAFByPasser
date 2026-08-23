import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import {
  AimOutlined,
  ApiOutlined,
  ApartmentOutlined,
  BookOutlined,
  BugOutlined,
  CodeOutlined,
  CopyOutlined,
  DatabaseOutlined,
  DashboardOutlined,
  FileAddOutlined,
  Html5Outlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  QuestionCircleOutlined,
  SafetyCertificateOutlined,
  StopOutlined,
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
  message,
} from 'antd'
import type { MenuProps, TabsProps } from 'antd'
import { api } from './api'
import './styles.css'

const { Header, Sider, Content } = Layout
const { Text, Title, Paragraph } = Typography

type VulnerabilityKey = 'command-injection' | 'file-upload' | 'sql-injection' | 'log4j' | 'xss'
type DirectWafTarget = { label: string; description: string }
type TencentWafState = { configured: boolean; ip?: string; host?: string; preflight_status?: number; preflight_result?: string; error?: string }
type CandidateStatus = 'pending_test' | 'test_success' | 'test_failed' | 'rejected' | 'archived'
type ArchiveOutcome = 'bypass_success' | 'bypass_failure'
type WorkspaceKey = 'dashboard' | 'library' | 'agent' | 'encoding' | 'cross' | 'waf' | 'targets' | 'unverified' | 'bypass-library' | 'block-library' | 'knowledge'

type KbTechnique = {
  id: string
  technique_id: string
  name: string | null
  vulnerability: string
  status: 'pending' | 'promoted' | 'pruned'
  success_count: number
  group: 'semantic' | 'encoding'
  labels: string[]
  source_note: string | null
}
type KbTechniqueStats = { semantic: { total: number; promoted: number }; encoding: { total: number; promoted: number } }
type KbAgentHandover = { semantic: { label: string; count: number }[]; encoding: { label: string; count: number }[] }

type VerificationTarget = {
  key: string
  label: string
  vulnerability: VulnerabilityKey
  base_url: string
  waf: string
  configured: boolean
  method: string
  injection_point: string
}

type WafTestResult = 'waf_blocked' | 'waf_bypassed' | 'application_response' | 'execution_confirmed' | 'inconclusive' | 'request_error'
type WafTestRun = {
  id: string; agent: 'semantic' | 'encoding' | 'cross'; candidate_id: string; base_name: string
  vulnerability: VulnerabilityKey; payload_snapshot: string; status: 'queued' | 'running' | 'completed' | 'failed'
  result: WafTestResult | null; evidence: string | null; request_summary: string | null; response_excerpt: string | null
  http_status: number | null; error_message: string | null; created_at: string; started_at: string | null; completed_at: string | null
}
type WafScene = { configured: boolean; base_url?: string; security?: string; supported: VulnerabilityKey[]; direct_targets?: Record<string, DirectWafTarget>; tencent_waf?: TencentWafState; error?: string }

type Payload = {
  id: string
  vulnerability: VulnerabilityKey
  delivery: string
  severity: '低危' | '中危' | '高危' | '严重'
  is_executable: boolean
  content: string
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
  mode: 'full' | 'partial' | 'legacy_unverified'
  submode?: string
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
  snapshot: {
    id: string
    name: string
    vulnerability: VulnerabilityKey
    category: string
    delivery: string
    target: string
    difficulty: string
    content: string
    severity?: Payload['severity']
    is_executable?: boolean
  }
}

type AgentDocument = {
  id: string
  kind: 'skill' | 'prompt'
  title: string
  content: string
}
type VerificationFailureStage = 'bypass_failed' | 'verify_failed' | 'check_error'
type VerificationVerdict = 'bypass' | 'block' | 'error'
type VerificationExecution = 'confirmed' | 'not_confirmed'

type BypassLibraryEntry = {
  id: string
  source_agent: 'semantic' | 'encoding' | 'cross'
  source_candidate_id: string
  candidate_kind: string
  name: string
  vulnerability: VulnerabilityKey
  delivery: string
  target_key: string
  content: string
  confidence: number
  rationale: string
  provenance: Record<string, unknown>
  created_at: string
  updated_at: string
}

type BlockLibraryEntry = BypassLibraryEntry & { failure_stage: VerificationFailureStage }
type UnverifiedLibraryEntry = BypassLibraryEntry

type VerificationJob = {
  id: string
  source_agent: 'semantic' | 'encoding' | 'cross'
  source_candidate_id: string
  candidate_kind: string
  base_name: string
  vulnerability: VulnerabilityKey
  payload_snapshot: string
  delivery: string
  status: 'queued' | 'running' | 'completed' | 'failed'
  target_key: string
  raw_evidence: Record<string, unknown> | null
  verdict: Record<string, unknown> | null
  bypass_verdict: VerificationVerdict | null
  execution_verdict: VerificationExecution | null
  failure_stage: VerificationFailureStage | null
  library_record_id: string | null
  error_message: string | null
  attempt_count: number
  created_at: string
  started_at: string | null
  completed_at: string | null
}

const vulnerabilityDefinitions: Record<VulnerabilityKey, { label: string; tagColor: string; icon: ReactNode; types: string[] }> = {
  'command-injection': { label: '命令注入', tagColor: 'volcano', icon: <CodeOutlined />, types: ['基础命令', '参数拼接', '编码变体'] },
  'file-upload': { label: '文件上传', tagColor: 'gold', icon: <UploadOutlined />, types: ['文件名校验', '内容校验', '路径处理'] },
  'sql-injection': { label: 'SQL 注入', tagColor: 'red', icon: <DatabaseOutlined />, types: ['通用语法', '布尔判定', '报错分析'] },
  log4j: { label: 'Log4j', tagColor: 'purple', icon: <BugOutlined />, types: ['环境确认', '日志触发', '编码变体'] },
  xss: { label: 'XSS', tagColor: 'cyan', icon: <Html5Outlined />, types: ['反射型', '存储型', 'DOM 型'] },
}

const vulnerabilityKeys = Object.keys(vulnerabilityDefinitions) as VulnerabilityKey[]
const deliveryOptions = ['URL 查询参数', '表单字段', 'JSON 请求体', 'multipart/form-data 文件字段', '请求头 / Cookie']
const encodingTypeLabels: Record<string, string> = {
  url: 'URL 百分号',
  url_fullwidth: 'URL 全角百分号',
  url_unicode: 'URL Unicode (IIS)',
  jetty_url: 'Jetty URL Unicode',
  html_dec: 'HTML 十进制实体',
  html_hex: 'HTML 十六进制实体',
  js_octal: 'JS 八进制转义',
  js_hex: 'JS 十六进制转义',
  js_unicode: 'JS Unicode 转义',
  hex: '十六进制文本',
  binary: '二进制文本',
  base64: 'Base64',
  base64_datauri: 'Base64 Data URI',
  quoted_printable: 'Quoted-Printable',
  utf7: 'UTF-7',
  cp037: 'CP-037 (EBCDIC)',
  utf16be: 'UTF-16BE',
  json: 'JSON 字符串转义',
  xml: 'XML 特殊字符转义',
  xml_entity: 'XML 十六进制实体',
  graphql: 'GraphQL 字符串转义',
  ghostbits: '零宽字符植入',
  comment_sql: 'SQL 注释分割',
  comment_html: 'HTML 注释分割',
  space_morph: '空白字符变形',
  case_morph: '大小写变形',
  gzip: 'gzip 压缩',
  php_serialize: 'PHP serialize 封装',
  legacy_semantic_boundary_migration: '历史语义边界迁移',
}

function encodingModeLabel(mode: EncodingStep['mode'], submode?: string) {
  if (mode === 'full') return '整句'
  if (mode === 'partial') return `部分[${submode || '部分'}]`
  if (mode === 'legacy_unverified') return '待新版重放复核'
  return mode
}

function encodingPrerequisites(chain: EncodingStep[]) {
  return ''
}

function deliveryFor(vulnerability: VulnerabilityKey) {
  if (vulnerability === 'file-upload') return 'multipart/form-data 文件字段'
  if (vulnerability === 'sql-injection') return 'URL 查询参数'
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

export function App() {
  const [messageApi, messageContext] = message.useMessage()
  const [collapsed, setCollapsed] = useState(false)
  const [workspace, setWorkspace] = useState<WorkspaceKey>('dashboard')
  const [libraryTab, setLibraryTab] = useState('source')
  const [agentTab, setAgentTab] = useState('workspace')
  const [encodingAgentTab, setEncodingAgentTab] = useState('workspace')
  const [payloads, setPayloads] = useState<Payload[]>([])
  const [payloadVulnPage, setPayloadVulnPage] = useState<Record<string, number>>({})
  const [payloadVulnTotal, setPayloadVulnTotal] = useState<Record<string, number>>({})
  const [candidates, setCandidates] = useState<Candidate[]>([])
  const [encodingCandidates, setEncodingCandidates] = useState<EncodingCandidate[]>([])
  const [crossSources, setCrossSources] = useState<CrossSource[]>([])
  const [crossCandidates, setCrossCandidates] = useState<CrossCandidate[]>([])
  const [bypassLibrary, setBypassLibrary] = useState<BypassLibraryEntry[]>([])
  const [blockLibrary, setBlockLibrary] = useState<BlockLibraryEntry[]>([])
  const [unverifiedLibrary, setUnverifiedLibrary] = useState<UnverifiedLibraryEntry[]>([])
  const [kbTechniques, setKbTechniques] = useState<KbTechnique[]>([])
  const [kbStats, setKbStats] = useState<KbTechniqueStats | null>(null)
  const [kbHandover, setKbHandover] = useState<KbAgentHandover | null>(null)
  const [kbArticle, setKbArticle] = useState('')
  const [kbArticleImporting, setKbArticleImporting] = useState(false)
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummary | null>(null)
  const [page, setPage] = useState({ payloads: 1, candidates: 1, encodingCandidates: 1, crossSources: 1, crossCandidates: 1, bypassLibrary: 1, blockLibrary: 1, unverifiedLibrary: 1 })
  const [totals, setTotals] = useState({ payloads: 0, candidates: 0, encodingCandidates: 0, crossSources: 0, crossCandidates: 0, bypassLibrary: 0, blockLibrary: 0, unverifiedLibrary: 0 })
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
  const [verificationTargets, setVerificationTargets] = useState<VerificationTarget[]>([])
  const [kbVulnFilter, setKbVulnFilter] = useState<string>('all')
  const [loading, setLoading] = useState(true)
  const [apiError, setApiError] = useState('')
  const [editingId, setEditingId] = useState<string | null>(null)
  const [expandedCard, setExpandedCard] = useState<string | null>(null)
  const [expandedCandidate, setExpandedCandidate] = useState<string | null>(null)
  const [expandedEncodingCandidate, setExpandedEncodingCandidate] = useState<string | null>(null)
  const [expandedCrossCandidate, setExpandedCrossCandidate] = useState<string | null>(null)
  const [editDraft, setEditDraft] = useState<{
    content: string
    delivery: string
    severity: Payload['severity']
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
    delivery: '表单字段',
    severity: '中危' as Payload['severity'],
    content: '',
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
    const loadError = (error: unknown) => {
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
      if (path.startsWith('/bypass-library')) return page.bypassLibrary
      if (path.startsWith('/block-library')) return page.blockLibrary
      if (path.startsWith('/unverified-library')) return page.unverifiedLibrary
      return page.payloads
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
      // payload 库按漏洞类型分 tab，每个 tab 独立分页，只加载当前 tab 的一页。
      if (libraryTab === 'source') {
        request = Promise.resolve()
      } else {
        const vulnPage = payloadVulnPage[libraryTab] || 1
        const cursor = (vulnPage - 1) * PAGE_SIZE
        request = api<PageResult<Payload>>(`/payloads?vulnerability=${encodeURIComponent(libraryTab)}&limit=${PAGE_SIZE}&cursor=${cursor}`).then((result) => {
          if (revision !== dataLoadRevision.current) return
          setPayloads(result.items)
          setPayloadVulnTotal((current) => ({ ...current, [libraryTab]: result.total }))
        })
      }
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
    } else if (workspace === 'bypass-library') {
      request = loadPage<BypassLibraryEntry>('/bypass-library').then((next) => applyPage('bypassLibrary', next, setBypassLibrary))
    } else if (workspace === 'block-library') {
      request = loadPage<BlockLibraryEntry>('/block-library').then((next) => applyPage('blockLibrary', next, setBlockLibrary))
    } else if (workspace === 'unverified') {
      request = loadPage<UnverifiedLibraryEntry>('/unverified-library').then((next) => applyPage('unverifiedLibrary', next, setUnverifiedLibrary))
    } else if (workspace === 'targets') {
      request = api<VerificationTarget[]>('/verification-targets').then((targets) => {
        if (revision === dataLoadRevision.current) setVerificationTargets(targets)
      })
    } else if (workspace === 'knowledge') {
      request = Promise.all([
        api<KbTechnique[]>('/kb-techniques').then(setKbTechniques),
        api<KbTechniqueStats>('/kb-techniques/stats').then(setKbStats),
        api<KbAgentHandover>('/kb-agent-handovers').then(setKbHandover),
      ]).then(() => undefined)
    } else {
      request = Promise.resolve()
    }
    request = request.catch(loadError).then(() => {
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
    try { await api<WafScene>('/waf-test-scene/preflight', { method: 'POST' }); await loadWafData(); messageApi.success('WAF 预检通过') }
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
  }, [workspace, page, libraryTab, payloadVulnPage])

  useEffect(() => {
    if (workspace === 'waf') void loadWafData()
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
      delivery: deliveryFor(vulnerability),
    }))
  }

  const createPayload = async () => {
    if (!draft.content.trim()) return
    try {
      await api<Payload>('/payloads', { method: 'POST', body: JSON.stringify(draft) })
      setDraft((current) => ({ ...current, content: '' }))
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
      content: payload.content,
      delivery: payload.delivery,
      severity: payload.severity,
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

  const addToCrossSources = async (payload: Payload) => {
    try {
      await api<CrossSource>('/cross-sources/from-payload', {
        method: 'POST',
        body: JSON.stringify({ source_payload_id: payload.id }),
      })
      messageApi.success('Payload 已加入正向交叉迭代来源')
      if (workspace === 'cross') await loadData()
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '加入正向交叉迭代失败')
    }
  }

  const saveEdit = async (payload: Payload) => {
    if (!editDraft?.content.trim()) return
    try {
      await api<Payload>(`/payloads/${payload.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          content: editDraft.content,
          delivery: editDraft.delivery,
          severity: editDraft.severity,
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

  const dashboardMetrics = useMemo(() => {
    if (dashboardSummary) {
      return {
        payloadCount: dashboardSummary.payload_count,
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
  }, [candidates, dashboardSummary, encodingCandidates, crossCandidates, payloads.length, semanticPool, encodingPool])

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
      { key: 'targets', icon: <AimOutlined />, label: '靶场管理' },
      { key: 'unverified', icon: <QuestionCircleOutlined />, label: '待人工验证' },
    ] },
    { type: 'group', label: '结果区', children: [
      { key: 'bypass-library', icon: <SafetyCertificateOutlined />, label: 'bypass库' },
      { key: 'block-library', icon: <StopOutlined />, label: 'block库' },
      { key: 'knowledge', icon: <BookOutlined />, label: '知识库管理' },
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
            <Form.Item label="恶意程度" required>
              <Select value={draft.severity} options={['低危', '中危', '高危', '严重'].map((severity) => ({ value: severity, label: severity }))} onChange={(severity) => setDraft((current) => ({ ...current, severity }))} />
            </Form.Item>
            <Form.Item label="投递方式" required>
              <Select value={draft.delivery} options={deliveryOptions.map((delivery) => ({ value: delivery, label: delivery }))} onChange={(delivery) => setDraft((current) => ({ ...current, delivery }))} />
            </Form.Item>
          </div>
          <Form.Item label="Payload 内容" required><Input.TextArea className="payload-editor" value={draft.content} rows={12} maxLength={5000} showCount onChange={(event) => setDraft((current) => ({ ...current, content: event.target.value }))} /></Form.Item>
          <div className="form-actions"><Button type="primary" htmlType="submit" icon={<FileAddOutlined />} disabled={!draft.content.trim()}>保存 Payload</Button></div>
        </Form>
      </Card>
      <Card className="workbench-card terminal-card" title={<Space><CodeOutlined />解析终端</Space>} extra={<span className="terminal-status">● LOCAL</span>}>
        <div className="terminal-window">
          <div className="terminal-line"><span>$</span> vulnerability: {vulnerabilityDefinitions[draft.vulnerability].label}</div>
          <div className="terminal-line"><span>$</span> severity: {draft.severity}</div>
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
          name: 'Payload 测试'
        })
      })
      await loadData()
      await loadWafData()
      messageApi.success('Payload 已发送到腾讯云测试场')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '发送到测试场失败')
    }
  }

  const payloadTab = (vulnerability: VulnerabilityKey) => {
    const definition = vulnerabilityDefinitions[vulnerability]
    const entries = payloads.filter((payload) => payload.vulnerability === vulnerability)
    const total = payloadVulnTotal[vulnerability] || entries.length
    const currentPage = payloadVulnPage[vulnerability] || 1
    return <div className="payload-list-layout">
      <div className="panel-heading payload-list-heading"><Space><Title level={5}>{definition.label}</Title><Tag color={definition.tagColor}>{total} 条</Tag></Space></div>
      {entries.length === 0 ? <Card className="empty-card" variant="borderless"><Empty description="暂无已验证 Payload" /></Card> : <>
        <div className="accordion-section-title">条目详情</div>
        <Collapse className="payload-accordion" accordion bordered={false} activeKey={expandedCard ? [expandedCard] : []} onChange={(key) => setExpandedCard(Array.isArray(key) ? key[0] || null : key || null)} items={entries.map((payload) => ({
          key: payload.id,
          label: <div className="payload-card-label"><div><Text strong code>{payload.content}</Text><div className="payload-card-meta"><Tag color="orange">{payload.severity}</Tag><Tag color="green">可执行</Tag><Tag color="geekblue">{payload.delivery}</Tag></div></div><div className="payload-card-actions"><Button type="primary" icon={<SafetyCertificateOutlined />} onClick={(event) => { event.stopPropagation(); void sendPayloadToTencentWaf(payload) }}>发送到测试场</Button><Button type="link" onClick={(event) => { event.stopPropagation(); void addToIterationPool('semantic', payload) }}>加入语义待迭代池</Button>{['command-injection', 'sql-injection', 'xss'].includes(payload.vulnerability) && <Button type="link" onClick={(event) => { event.stopPropagation(); void addToIterationPool('encoding', payload) }}>加入编码待迭代池</Button>}<Button type="link" onClick={(event) => { event.stopPropagation(); void addToCrossSources(payload) }}>加入正向交叉迭代</Button><Button type="link" onClick={(event) => { event.stopPropagation(); beginEdit(payload) }}>修改</Button><Popconfirm title="删除该条目？" onConfirm={() => void deletePayload(payload)}><Button danger type="link" onClick={(event) => event.stopPropagation()}>删除</Button></Popconfirm></div></div>,
          children: editingId === payload.id && editDraft ? <div className="payload-card-editor"><Input.TextArea rows={8} value={editDraft.content} onChange={(event) => setEditDraft((current) => current ? { ...current, content: event.target.value } : current)} /><Select value={editDraft.severity} options={['低危', '中危', '高危', '严重'].map((severity) => ({ value: severity, label: severity }))} onChange={(severity) => setEditDraft((current) => current ? { ...current, severity } : current)} /><Select value={editDraft.delivery} options={deliveryOptions.map((delivery) => ({ value: delivery, label: delivery }))} onChange={(delivery) => setEditDraft((current) => current ? { ...current, delivery } : current)} /><Space><Button type="primary" size="small" disabled={!editDraft.content.trim()} onClick={() => void saveEdit(payload)}>保存修改</Button><Button size="small" onClick={() => { setEditingId(null); setEditDraft(null) }}>取消</Button></Space></div> : <div className="payload-inline-detail"><div className="payload-detail-section"><Text type="secondary">Payload 内容</Text><pre>{payload.content}</pre></div><div className="payload-detail-section"><Tag color="orange">{payload.severity}</Tag><Tag color="green">可执行</Tag></div></div>,
        }))} />
      </>}
      {total > PAGE_SIZE ? <Pagination
        className="list-pagination"
        size="small"
        current={currentPage}
        pageSize={PAGE_SIZE}
        total={total}
        showSizeChanger={false}
        onChange={(next) => setPayloadVulnPage((current) => ({ ...current, [vulnerability]: next }))}
      /> : null}
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
      children: <div className="candidate-detail">{candidatePayloadBlock('编码后 Payload', candidate.content)}{candidate.origin === 'semantic_boundary_migration' && <Alert type="warning" showIcon title="历史语义边界迁移" description={candidate.migration_note || '该候选来自旧版语义队列，未按新版编码重放器生成，请人工复核其解释前提。'} />}<div className="encoding-path"><Text strong>编码链：</Text><span>{candidate.encoding_chain.map((step) => `${encodingTypeLabels[step.type] || step.type}（${encodingModeLabel(step.mode, step.submode)}）`).join(' → ')}</span></div><div className="encoding-path"><Text strong>预期解码路径：</Text><span>{candidate.decode_path.map((step) => encodingTypeLabels[step] || step).join(' → ')}</span></div>{encodingPrerequisites(candidate.encoding_chain) && <Paragraph type="secondary">{encodingPrerequisites(candidate.encoding_chain)}</Paragraph>}<Paragraph type="secondary">{candidate.explanation}</Paragraph>{candidate.status === 'pending_test' && <div className="candidate-actions"><Input placeholder="手工测试记录（可选）" value={encodingTestNotes[candidate.id] || ''} onClick={(event) => event.stopPropagation()} onChange={(event) => setEncodingTestNotes((current) => ({ ...current, [candidate.id]: event.target.value }))} /><Space><Button size="small" type="primary" onClick={() => void updateEncodingCandidate(candidate, 'test_success')}>标记测试成功</Button><Button size="small" danger onClick={() => void updateEncodingCandidate(candidate, 'test_failed')}>标记测试失败</Button><Button size="small" onClick={() => void updateEncodingCandidate(candidate, 'rejected')}>拒绝</Button></Space></div>}{archiveCandidateControls(candidate, 'encoding')}{candidate.test_note && <Paragraph type="secondary">测试记录：{candidate.test_note}</Paragraph>}</div>,
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
      children: <div className="candidate-detail"><div className="candidate-payload-block"><div className="candidate-content-heading"><Text type="secondary">语义来源 Payload</Text></div><pre className="candidate-content">{candidate.semantic_content}</pre></div>{candidatePayloadBlock('编码后 Payload', candidate.content)}<div className="encoding-path"><Text strong>编码链：</Text><span>{candidate.encoding_chain.map((step) => `${encodingTypeLabels[step.type] || step.type}（${encodingModeLabel(step.mode, step.submode)}）`).join(' → ')}</span></div><div className="encoding-path"><Text strong>预期解码路径：</Text><span>{candidate.decode_path.map((step) => encodingTypeLabels[step] || step).join(' → ')}</span></div>{candidate.status === 'pending_test' && <div className="candidate-actions"><Input placeholder="手工测试记录（可选）" value={crossTestNotes[candidate.id] || ''} onClick={(event) => event.stopPropagation()} onChange={(event) => setCrossTestNotes((current) => ({ ...current, [candidate.id]: event.target.value }))} /><Space><Button size="small" type="primary" onClick={() => void updateCrossCandidate(candidate, 'test_success')}>标记测试成功</Button><Button size="small" danger onClick={() => void updateCrossCandidate(candidate, 'test_failed')}>标记测试失败</Button><Button size="small" onClick={() => void updateCrossCandidate(candidate, 'rejected')}>拒绝</Button></Space></div>}{candidate.status === 'test_success' && <Button size="small" onClick={() => void updateCrossCandidate(candidate, 'pending_test')}>取消成功标记</Button>}{candidate.status === 'test_failed' && <Button size="small" onClick={() => void updateCrossCandidate(candidate, 'pending_test')}>取消失败标记</Button>}{candidate.test_note && <Paragraph type="secondary">测试记录：{candidate.test_note}</Paragraph>}</div>,
    }))} />}
    {pageControl('crossCandidates')}
  </div></section>

  const verificationAgentLabels: Record<BypassLibraryEntry['source_agent'], string> = {
    semantic: '语义迭代',
    encoding: '编码迭代',
    cross: '交叉迭代',
  }
  const failureStageLabels: Record<VerificationFailureStage, { label: string; color: string }> = {
    bypass_failed: { label: '绕过失败', color: 'red' },
    verify_failed: { label: '验证失败', color: 'orange' },
    check_error: { label: '检验异常', color: 'default' },
  }
  const bypassLibraryColumns = [
    { title: '名称', dataIndex: 'name', key: 'name', ellipsis: true },
    { title: '来源', dataIndex: 'source_agent', key: 'source_agent', width: 110, render: (agent: BypassLibraryEntry['source_agent']) => <Tag color={agent === 'cross' ? 'purple' : agent === 'encoding' ? 'cyan' : 'blue'}>{verificationAgentLabels[agent]}</Tag> },
    { title: '漏洞', dataIndex: 'vulnerability', key: 'vulnerability', width: 105, render: (vulnerability: VulnerabilityKey) => vulnerabilityDefinitions[vulnerability].label },
    { title: '靶场', dataIndex: 'target_key', key: 'target_key', width: 150, ellipsis: true },
    { title: '投递方式', dataIndex: 'delivery', key: 'delivery', width: 150, ellipsis: true },
    { title: '置信度', dataIndex: 'confidence', key: 'confidence', width: 90, render: (confidence: number) => <Tag color="green">{(confidence * 100).toFixed(0)}%</Tag> },
    { title: '标签', key: 'tags', width: 180, render: () => <Space size={4}><Tag color="green">绕过成功</Tag><Tag color="green">验证成功</Tag></Space> },
  ]
  const blockLibraryColumns = [
    { title: '名称', dataIndex: 'name', key: 'name', ellipsis: true },
    { title: '来源', dataIndex: 'source_agent', key: 'source_agent', width: 110, render: (agent: BypassLibraryEntry['source_agent']) => <Tag color={agent === 'cross' ? 'purple' : agent === 'encoding' ? 'cyan' : 'blue'}>{verificationAgentLabels[agent]}</Tag> },
    { title: '漏洞', dataIndex: 'vulnerability', key: 'vulnerability', width: 105, render: (vulnerability: VulnerabilityKey) => vulnerabilityDefinitions[vulnerability].label },
    { title: '靶场', dataIndex: 'target_key', key: 'target_key', width: 150, ellipsis: true },
    { title: '投递方式', dataIndex: 'delivery', key: 'delivery', width: 150, ellipsis: true },
    { title: '失败环节', dataIndex: 'failure_stage', key: 'failure_stage', width: 110, render: (stage: VerificationFailureStage) => <Tag color={failureStageLabels[stage].color}>{failureStageLabels[stage].label}</Tag> },
  ]
  const unverifiedLibraryColumns = [
    { title: '名称', dataIndex: 'name', key: 'name', ellipsis: true },
    { title: '来源', dataIndex: 'source_agent', key: 'source_agent', width: 110, render: (agent: BypassLibraryEntry['source_agent']) => <Tag color={agent === 'cross' ? 'purple' : agent === 'encoding' ? 'cyan' : 'blue'}>{verificationAgentLabels[agent]}</Tag> },
    { title: '漏洞', dataIndex: 'vulnerability', key: 'vulnerability', width: 105, render: (vulnerability: VulnerabilityKey) => vulnerabilityDefinitions[vulnerability].label },
    { title: '靶场', dataIndex: 'target_key', key: 'target_key', width: 150, ellipsis: true },
    { title: '投递方式', dataIndex: 'delivery', key: 'delivery', width: 150, ellipsis: true },
    { title: '标签', key: 'tags', width: 110, render: () => <Tag color="orange">待人工验证</Tag> },
  ]
  const libraryDetail = (entry: BypassLibraryEntry) => <div className="candidate-detail">
    <Text type="secondary">Payload 内容</Text><pre className="candidate-content">{entry.content}</pre>
    <Paragraph type="secondary">判定依据：{entry.rationale || '无'}</Paragraph>
    <Text type="secondary">来源链路</Text><pre className="candidate-content">{JSON.stringify(entry.provenance, null, 2)}</pre>
  </div>
  const bypassLibraryWorkspace = workspace === 'bypass-library' && <section className="workspace-card payload-workspace"><div className="samples-workspace">
    <div className="panel-heading"><Space><SafetyCertificateOutlined /><Title level={5}>bypass 库</Title><Tag color="green">{bypassLibrary.length} 条</Tag></Space><Text type="secondary">绕过成功 + 验证成功的 Payload 结果。</Text></div>
    {bypassLibrary.length === 0 ? <Card className="empty-card" variant="borderless"><Empty description="暂无 bypass 结果" /></Card> : <><Card className="workbench-card payload-table-card" title="bypass 索引" size="small"><Table<BypassLibraryEntry> className="payload-table" rowKey="id" size="small" pagination={false} columns={bypassLibraryColumns} dataSource={bypassLibrary} /></Card>{pageControl('bypassLibrary')}<div className="accordion-section-title">条目详情</div><Collapse className="candidate-accordion" accordion bordered={false} items={bypassLibrary.map((entry) => ({ key: entry.id, label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong>{entry.name}</Text><div className="candidate-card-meta"><Tag color={entry.source_agent === 'cross' ? 'purple' : entry.source_agent === 'encoding' ? 'cyan' : 'blue'}>{verificationAgentLabels[entry.source_agent]}</Tag><Tag color={vulnerabilityDefinitions[entry.vulnerability].tagColor}>{vulnerabilityDefinitions[entry.vulnerability].label}</Tag><Tag color="green">绕过成功</Tag><Tag color="green">验证成功</Tag></div></div></div>, children: libraryDetail(entry) }))} /></>}
  </div></section>
  const blockLibraryWorkspace = workspace === 'block-library' && <section className="workspace-card payload-workspace"><div className="samples-workspace">
    <div className="panel-heading"><Space><StopOutlined /><Title level={5}>block 库</Title><Tag color="red">{blockLibrary.length} 条</Tag></Space><Text type="secondary">未同时满足绕过成功 + 验证成功的 Payload，按失败环节分类。</Text></div>
    {blockLibrary.length === 0 ? <Card className="empty-card" variant="borderless"><Empty description="暂无 block 结果" /></Card> : <><Card className="workbench-card payload-table-card" title="block 索引" size="small"><Table<BlockLibraryEntry> className="payload-table" rowKey="id" size="small" pagination={false} columns={blockLibraryColumns} dataSource={blockLibrary} /></Card>{pageControl('blockLibrary')}<div className="accordion-section-title">条目详情</div><Collapse className="candidate-accordion" accordion bordered={false} items={blockLibrary.map((entry) => ({ key: entry.id, label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong>{entry.name}</Text><div className="candidate-card-meta"><Tag color={entry.source_agent === 'cross' ? 'purple' : entry.source_agent === 'encoding' ? 'cyan' : 'blue'}>{verificationAgentLabels[entry.source_agent]}</Tag><Tag color={vulnerabilityDefinitions[entry.vulnerability].tagColor}>{vulnerabilityDefinitions[entry.vulnerability].label}</Tag><Tag color={failureStageLabels[entry.failure_stage].color}>{failureStageLabels[entry.failure_stage].label}</Tag></div></div></div>, children: libraryDetail(entry) }))} /></>}
  </div></section>
  const resolveUnverified = async (entry: UnverifiedLibraryEntry, outcome: 'confirmed' | 'failed') => {
    try {
      await api(`/unverified-library/${entry.id}/resolve`, { method: 'POST', body: JSON.stringify({ outcome }) })
      messageApi.success(outcome === 'confirmed' ? '已确认成功，转入 bypass 库' : '已确认失败，转入 block 库')
      await loadData()
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '人工复核失败')
    }
  }
  const unverifiedDetail = (entry: UnverifiedLibraryEntry) => <div className="candidate-detail">
    {libraryDetail(entry)}
    <div className="candidate-actions" style={{ marginTop: 12 }}>
      <Space>
        <Button type="primary" size="small" onClick={() => void resolveUnverified(entry, 'confirmed')}>确认成功</Button>
        <Button danger size="small" onClick={() => void resolveUnverified(entry, 'failed')}>确认失败</Button>
      </Space>
    </div>
  </div>
  const unverifiedLibraryWorkspace = workspace === 'unverified' && <section className="workspace-card payload-workspace"><div className="samples-workspace">
    <div className="panel-heading"><Space><QuestionCircleOutlined /><Title level={5}>待人工验证</Title><Tag color="orange">{unverifiedLibrary.length} 条</Tag></Space><Text type="secondary">无法自动闭环验证的 Payload（外带/盲注/OOB 等），需人工确认是否执行成功。</Text></div>
    {unverifiedLibrary.length === 0 ? <Card className="empty-card" variant="borderless"><Empty description="暂无待人工验证结果" /></Card> : <><Card className="workbench-card payload-table-card" title="待验证索引" size="small"><Table<UnverifiedLibraryEntry> className="payload-table" rowKey="id" size="small" pagination={false} columns={unverifiedLibraryColumns} dataSource={unverifiedLibrary} /></Card>{pageControl('unverifiedLibrary')}<div className="accordion-section-title">条目详情</div><Collapse className="candidate-accordion" accordion bordered={false} items={unverifiedLibrary.map((entry) => ({ key: entry.id, label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong>{entry.name}</Text><div className="candidate-card-meta"><Tag color={entry.source_agent === 'cross' ? 'purple' : entry.source_agent === 'encoding' ? 'cyan' : 'blue'}>{verificationAgentLabels[entry.source_agent]}</Tag><Tag color={vulnerabilityDefinitions[entry.vulnerability].tagColor}>{vulnerabilityDefinitions[entry.vulnerability].label}</Tag><Tag color="orange">待人工验证</Tag></div></div></div>, children: unverifiedDetail(entry) }))} /></>}
  </div></section>


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

  const wafSceneUsesLegacyApi = Boolean(wafScene && wafScene.direct_targets === undefined)
  const staleWafBackendAlert = <Alert
    type="warning"
    showIcon
    title="后端版本未更新"
    description="当前 FastAPI 仍在返回旧版测试场接口，请重启 127.0.0.1:8000 后刷新页面。"
  />

  const wafWorkspace = workspace === 'waf' && <section className="workspace-card payload-workspace">
    <Tabs defaultActiveKey="tencent" items={[
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

  // ── 靶场管理 ──────────────────────────────────────────────
  const targetsColumns = [
    { title: '靶场', dataIndex: 'label', key: 'label', ellipsis: true },
    { title: '覆盖漏洞', dataIndex: 'vulnerability', key: 'vulnerability', width: 130, render: (vulnerability: VulnerabilityKey) => <Tag color={vulnerabilityDefinitions[vulnerability].tagColor}>{vulnerabilityDefinitions[vulnerability].label}</Tag> },
    { title: '请求方式', dataIndex: 'method', key: 'method', width: 100 },
    { title: '注入点', dataIndex: 'injection_point', key: 'injection_point', ellipsis: true },
    { title: 'WAF', dataIndex: 'waf', key: 'waf', width: 120, render: (waf: string) => <Tag color="geekblue">{waf}</Tag> },
    { title: '状态', dataIndex: 'configured', key: 'configured', width: 100, render: (configured: boolean) => configured ? <Tag color="green">已配置</Tag> : <Tag color="orange">未配置</Tag> },
  ]
  const targetsWorkspace = workspace === 'targets' && <section className="workspace-card payload-workspace">
    <div className="panel-heading"><Space><AimOutlined /><Title level={5}>靶场管理</Title><Tag color="blue">{verificationTargets.length} 个靶场</Tag></Space><Text type="secondary">检验 Agent 自动路由到的靶场注册表，配置来自 config/.env。</Text></div>
    <Card className="workbench-card" size="small" title="靶场列表">
      <Table<VerificationTarget> className="payload-table" rowKey="key" size="small" pagination={false} columns={targetsColumns} dataSource={verificationTargets} expandable={{
        expandedRowRender: (target) => <div className="candidate-detail">
          <Text type="secondary">靶场地址</Text><pre className="candidate-content">{target.base_url || '（未配置）'}</pre>
          <Text type="secondary">注入点</Text><pre className="candidate-content">{target.injection_point}</pre>
        </div>,
      }} />
    </Card>
  </section>

  // ── 知识库管理 ──────────────────────────────────────────────
  const kbTechniqueColumns = [
    { title: '技巧', dataIndex: 'technique_id', key: 'technique_id', ellipsis: true, render: (id: string) => <Text code>{id}</Text> },
    { title: '名称', dataIndex: 'name', key: 'name', ellipsis: true },
    { title: '漏洞', dataIndex: 'vulnerability', key: 'vulnerability', width: 130, render: (v: string) => <Tag color={vulnerabilityDefinitions[v as VulnerabilityKey]?.tagColor || 'default'}>{vulnerabilityDefinitions[v as VulnerabilityKey]?.label || v}</Tag> },
    { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (s: string) => s === 'promoted' ? <Tag color="green">已转正</Tag> : <Tag color="orange">待验证</Tag> },
    { title: '成功次数', dataIndex: 'success_count', key: 'success_count', width: 100 },
  ]
  const kbTechniqueGroup = (group: 'semantic' | 'encoding', vuln: string = 'all') => kbTechniques.filter((t) => t.group === group && (vuln === 'all' || t.vulnerability === vuln))
  const kbGroupStats = (group: 'semantic' | 'encoding') => kbStats?.[group] ?? { total: 0, promoted: 0 }
  const kbGroupHandover = (group: 'semantic' | 'encoding') => (kbHandover?.[group] ?? []).slice(0, 20)
  const kbImportArticle = async () => {
    if (!kbArticle.trim()) return
    setKbArticleImporting(true)
    try {
      const result = await api<{ inserted: number; parsed: number }>('/kb-techniques/import', { method: 'POST', body: JSON.stringify({ content: kbArticle, source_name: `manual_${Date.now()}.md` }) })
      messageApi.success(`文章导入成功：解析 ${result.parsed} 条，写入 ${result.inserted} 条`)
      setKbArticle('')
      setKbTechniques(await api<KbTechnique[]>('/kb-techniques'))
      setKbStats(await api<KbTechniqueStats>('/kb-techniques/stats'))
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '文章导入失败')
    } finally {
      setKbArticleImporting(false)
    }
  }
  const kbVulnTabs = (group: 'semantic' | 'encoding', handover: { label: string; count: number }[], tagColor: string) => (
    <Tabs
      defaultActiveKey="all"
      activeKey={kbVulnFilter}
      onChange={setKbVulnFilter}
      items={[
        { key: 'all', label: '全部' },
        ...vulnerabilityKeys.map((vuln) => ({ key: vuln, label: vulnerabilityDefinitions[vuln].label })),
      ].map((tab) => ({
        ...tab,
        children: <div className="samples-workspace">
          <Card className="workbench-card" size="small" title={`${group === 'semantic' ? '语义' : '编码'}绕过手法 · ${tab.key === 'all' ? '全部' : vulnerabilityDefinitions[tab.key as VulnerabilityKey].label}（${kbTechniqueGroup(group, tab.key).length} 条）`}>
            <Table<KbTechnique> rowKey="id" size="small" pagination={{ pageSize: 20 }} columns={kbTechniqueColumns} dataSource={kbTechniqueGroup(group, tab.key)} />
          </Card>
          <Card className="workbench-card" size="small" title={`Agent 实际手法统计（${group === 'semantic' ? 'rule_labels' : '编码链'} 频次）`} style={{ marginTop: 12 }}>
            {handover.length === 0 ? <Empty description="暂无统计" /> : <Space wrap>{handover.map((h) => <Tag key={h.label} color={tagColor}>{h.label} ×{h.count}</Tag>)}</Space>}
          </Card>
        </div>,
      }))}
    />
  )
  const knowledgeWorkspace = workspace === 'knowledge' && <section className="workspace-card payload-workspace">
    <div className="panel-heading"><Space><BookOutlined /><Title level={5}>知识库管理</Title><Tag color="blue">{kbTechniques.length} 条技巧</Tag></Space><Text type="secondary">绕过手法知识库 + 教材文章输入，检验双成功三次后技巧转正。</Text></div>
    <Tabs defaultActiveKey="semantic" items={[
      { key: 'semantic', label: '语义绕过手法', children: kbVulnTabs('semantic', kbGroupHandover('semantic'), 'blue') },
      { key: 'encoding', label: '编码绕过手法', children: kbVulnTabs('encoding', kbGroupHandover('encoding'), 'cyan') },
      { key: 'article', label: '文章输入', children: <div className="samples-workspace">
        <Card className="workbench-card" size="small" title="教材文章输入">
          <Text type="secondary">粘贴任意教材文章（无需固定格式），由知识库 Agent 自动浓缩提取其中的绕过技巧并入库。</Text>
          <Input.TextArea rows={14} placeholder="在此粘贴教材文章…" value={kbArticle} onChange={(event) => setKbArticle(event.target.value)} style={{ marginTop: 12, marginBottom: 12 }} />
          <Button type="primary" icon={<BookOutlined />} loading={kbArticleImporting} disabled={!kbArticle.trim()} onClick={() => void kbImportArticle()}>导入文章</Button>
        </Card>
      </div> },
    ]} />
  </section>


  const workspaceLabels: Record<WorkspaceKey, string> = {
    dashboard: '项目仪表盘',
    library: 'Payload 库',
    agent: '语义迭代 Agent',
    encoding: '编码绕过 Agent',
    cross: '正向交叉迭代',
    waf: 'WAF 测试场',
    targets: '靶场管理',
    unverified: '待人工验证',
    'bypass-library': 'bypass库',
    'block-library': 'block库',
    knowledge: '知识库管理',
  }

  const workspaceContent = workspace === 'dashboard'
    ? dashboardWorkspace
    : workspace === 'library'
    ? <section className="workspace-card payload-workspace"><Tabs activeKey={libraryTab} onChange={setLibraryTab} items={libraryTabs} /></section>
    : workspace === 'agent' ? agentWorkspace : workspace === 'encoding' ? encodingWorkspace : workspace === 'cross' ? crossWorkspace : workspace === 'waf' ? wafWorkspace : workspace === 'targets' ? targetsWorkspace : workspace === 'unverified' ? unverifiedLibraryWorkspace : workspace === 'knowledge' ? knowledgeWorkspace : workspace === 'bypass-library' ? bypassLibraryWorkspace : workspace === 'block-library' ? blockLibraryWorkspace : bypassLibraryWorkspace

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
