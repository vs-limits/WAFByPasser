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
  DownloadOutlined,
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
type CandidateStatus = 'pending_test' | 'test_success' | 'test_failed' | 'rejected' | 'archived'
type VerificationStatus = 'waiting' | 'queued' | 'running' | 'completed' | 'failed'
type ArchiveOutcome = 'bypass_success' | 'bypass_failure'
type WorkspaceKey = 'dashboard' | 'library' | 'agent' | 'encoding' | 'cross' | 'waf' | 'targets' | 'unverified' | 'bypass-library' | 'block-library' | 'knowledge'

type KbTechnique = {
  id: string
  technique_id: string
  name: string | null
  vulnerability: string
  status: 'seed' | 'frontier' | 'promoted' | 'retired'
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

type WafTestRun = {
  id: string; agent: 'semantic' | 'encoding' | 'cross'; candidate_id: string; base_name: string
  vulnerability: VulnerabilityKey; payload_snapshot: string; status: 'queued' | 'running' | 'completed' | 'failed'
  result: string | null; evidence: string | null; request_summary: string | null; response_excerpt: string | null
  http_status: number | null; error_message: string | null; created_at: string; started_at: string | null; completed_at: string | null
}

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
  verification_status?: VerificationStatus | null
  used_direction_ids: string[]
  next_directions: IterationDirection[]
  technique_ids: string[]
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
  verification_status?: VerificationStatus | null
  used_direction_ids: string[]
  next_directions: IterationDirection[]
  technique_ids: string[]
}

type EncodingTask = {
  id: string
  status: 'queued' | 'running' | 'completed' | 'failed'
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
  verification_status?: VerificationStatus | null
}

type CrossTask = {
  id: string
  status: 'completed' | 'failed'
  error_message?: string | null
  candidates: CrossCandidate[]
}

type PageResult<T> = { items: T[]; total: number; next_cursor: number | null }
type DashboardSummary = {
  payload_count: number
  technique_count: number
  bypass_library_count: number
  block_library_count: number
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

type CrossPoolItem = {
  id: string
  cross_source_id: string
  status: 'pending' | 'started'
  task_id: string | null
  task_status: 'queued' | 'running' | 'completed' | 'failed' | 'unknown' | null
  task_error: string | null
  created_at: string
  started_at: string | null
  source: {
    id: string
    name: string
    vulnerability: VulnerabilityKey
    category: string
    delivery: string
    target: string
    difficulty: string
    content: string
    rule_labels: string[]
  }
}

type VerificationFailureStage = 'bypass_failed' | 'verify_failed' | 'check_error'
type VerificationVerdict = 'bypass' | 'block' | 'error'
type VerificationExecution = 'confirmed' | 'not_confirmed' | 'unverified'

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
  techniques: { id: string; name: string }[]
  encoding_chain: EncodingStep[]
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

function verificationStatusTag(status?: VerificationStatus | null) {
  if (!status) return null
  const config: Record<VerificationStatus, [string, string]> = {
    waiting: ['default', '等待检验'],
    queued: ['blue', '排队检验'],
    running: ['processing', '检验中'],
    completed: ['green', '已检验'],
    failed: ['red', '检验失败'],
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
  const [payloads, setPayloads] = useState<Payload[]>([])
  const [payloadVulnPage, setPayloadVulnPage] = useState<Record<string, number>>({})
  const [payloadVulnTotal, setPayloadVulnTotal] = useState<Record<string, number>>({})
  const [candidates, setCandidates] = useState<Candidate[]>([])
  const [encodingCandidates, setEncodingCandidates] = useState<EncodingCandidate[]>([])
  const [crossSources, setCrossSources] = useState<CrossSource[]>([])
  const [crossCandidates, setCrossCandidates] = useState<CrossCandidate[]>([])
  const [bypassLibrary, setBypassLibrary] = useState<BypassLibraryEntry[]>([])
  const [bypassVulnTab, setBypassVulnTab] = useState<VulnerabilityKey>('command-injection')
  const [bypassVulnPage, setBypassVulnPage] = useState<Record<string, number>>({})
  const [bypassVulnTotal, setBypassVulnTotal] = useState<Record<string, number>>({})
  const [blockLibrary, setBlockLibrary] = useState<BlockLibraryEntry[]>([])
  const [blockVulnTab, setBlockVulnTab] = useState<VulnerabilityKey>('command-injection')
  const [blockVulnPage, setBlockVulnPage] = useState<Record<string, number>>({})
  const [blockVulnTotal, setBlockVulnTotal] = useState<Record<string, number>>({})
  const [unverifiedLibrary, setUnverifiedLibrary] = useState<UnverifiedLibraryEntry[]>([])
  const [kbTechniques, setKbTechniques] = useState<KbTechnique[]>([])
  const [kbStats, setKbStats] = useState<KbTechniqueStats | null>(null)
  const [kbHandover, setKbHandover] = useState<KbAgentHandover | null>(null)
  const [kbArticle, setKbArticle] = useState('')
  const [kbArticleVuln, setKbArticleVuln] = useState<VulnerabilityKey>('sql-injection')
  const [kbArticleImporting, setKbArticleImporting] = useState(false)
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummary | null>(null)
  const [page, setPage] = useState({ payloads: 1, candidates: 1, encodingCandidates: 1, crossSources: 1, crossCandidates: 1, bypassLibrary: 1, blockLibrary: 1, unverifiedLibrary: 1 })
  const [totals, setTotals] = useState({ payloads: 0, candidates: 0, encodingCandidates: 0, crossSources: 0, crossCandidates: 0, bypassLibrary: 0, blockLibrary: 0, unverifiedLibrary: 0 })
  const dataLoadRevision = useRef(0)
  const dataLoadPromise = useRef<Promise<void> | null>(null)
  const dataLoadingRequested = useRef(false)
  const semanticPollPromise = useRef<Promise<void> | null>(null)
  const encodingPollPromise = useRef<Promise<void> | null>(null)
  const [semanticPool, setSemanticPool] = useState<IterationPoolItem[]>([])
  const [encodingPool, setEncodingPool] = useState<IterationPoolItem[]>([])
  const [crossPool, setCrossPool] = useState<CrossPoolItem[]>([])
  const [verificationJobs, setVerificationJobs] = useState<VerificationJob[]>([])
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
  const [activeTask, setActiveTask] = useState<IterationTask | null>(null)
  const [activeEncodingTask, setActiveEncodingTask] = useState<EncodingTask | null>(null)
  const [activeCrossTask, setActiveCrossTask] = useState<CrossTask | null>(null)
  const [generating, setGenerating] = useState(false)
  const [encodingGenerating, setEncodingGenerating] = useState(false)
  const [crossGenerating, setCrossGenerating] = useState(false)
  const [draft, setDraft] = useState({
    vulnerability: 'command-injection' as VulnerabilityKey,
    delivery: '表单字段',
    severity: '中危' as Payload['severity'],
    content: '',
  })

  const selectedBase = payloads.find((payload) => payload.id === selectedBaseId)
  const selectedEncodingBase = payloads.find((payload) => payload.id === selectedEncodingBaseId)

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
        api<CrossPoolItem[]>('/iteration-pools/cross'),
      ]).then(([nextSources, nextCandidates, nextPool]) => {
        applyPage('crossSources', nextSources, setCrossSources)
        applyPage('crossCandidates', nextCandidates, setCrossCandidates)
        if (revision === dataLoadRevision.current) setCrossPool(nextPool)
      })
    } else if (workspace === 'bypass-library') {
      // bypass 库按漏洞类型分 tab 展示，每 tab 独立分页，只加载当前 tab 的一页。
      const vulnPage = bypassVulnPage[bypassVulnTab] || 1
      const cursor = (vulnPage - 1) * PAGE_SIZE
      request = api<PageResult<BypassLibraryEntry>>(`/bypass-library?vulnerability=${encodeURIComponent(bypassVulnTab)}&limit=${PAGE_SIZE}&cursor=${cursor}`).then((result) => {
        if (revision !== dataLoadRevision.current) return
        setBypassLibrary(result.items)
        setBypassVulnTotal((current) => ({ ...current, [bypassVulnTab]: result.total }))
      })
    } else if (workspace === 'block-library') {
      // block 库按漏洞类型分 tab 展示，每 tab 独立分页，只加载当前 tab 的一页。
      const vulnPage = blockVulnPage[blockVulnTab] || 1
      const cursor = (vulnPage - 1) * PAGE_SIZE
      request = api<PageResult<BlockLibraryEntry>>(`/block-library?vulnerability=${encodeURIComponent(blockVulnTab)}&limit=${PAGE_SIZE}&cursor=${cursor}`).then((result) => {
        if (revision !== dataLoadRevision.current) return
        setBlockLibrary(result.items)
        setBlockVulnTotal((current) => ({ ...current, [blockVulnTab]: result.total }))
      })
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

  const loadVerificationJobs = async () => {
    try {
      const jobs = await api<VerificationJob[]>('/verification-jobs')
      setVerificationJobs(jobs)
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '无法读取检验记录')
    }
  }

  const refreshCandidates = async () => {
    // 轻量刷新候选列表（不触发 loadData 全量重载），供生成任务运行中实时看到逐批落库的候选。
    const [semantic, encoding] = await Promise.all([
      api<PageResult<Candidate>>(`/candidates?limit=${PAGE_SIZE}&cursor=${(page.candidates - 1) * PAGE_SIZE}`).catch(() => null),
      api<PageResult<EncodingCandidate>>(`/encoding-candidates?limit=${PAGE_SIZE}&cursor=${(page.encodingCandidates - 1) * PAGE_SIZE}`).catch(() => null),
    ])
    if (semantic) {
      setCandidates(semantic.items)
      setTotals((current) => ({ ...current, candidates: semantic.total }))
    }
    if (encoding) {
      setEncodingCandidates(encoding.items)
      setTotals((current) => ({ ...current, encodingCandidates: encoding.total }))
    }
  }

  useEffect(() => {
    void loadData(workspace === 'dashboard')
  }, [workspace, page, libraryTab, payloadVulnPage, bypassVulnTab, bypassVulnPage, blockVulnTab, blockVulnPage])

  useEffect(() => {
    if (workspace === 'waf') void loadVerificationJobs()
  }, [workspace])

  useEffect(() => {
    if (!activeTask || !['queued', 'running'].includes(activeTask.status)) return
    const timer = window.setInterval(() => {
      if (semanticPollPromise.current) return
      const request = (async () => {
      try {
        const task = await api<IterationTask>(`/semantic-iterations/${activeTask.id}`)
        setActiveTask(task)
        if (['queued', 'running'].includes(task.status)) {
          await refreshCandidates()
        } else {
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
        if (['queued', 'running'].includes(task.status)) {
          await refreshCandidates()
        } else {
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
        setWorkspace(agent === 'semantic' ? 'agent' : 'encoding')
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
      const task = await api<{ id: string; status: 'queued' }>('/semantic-iterations', {
        method: 'POST',
        body: JSON.stringify({ base_payload_id: selectedBaseId }),
      })
      setActiveTask({ id: task.id, status: task.status, candidates: [] })
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
      const task = await api<{ id: string; status: 'queued' }>('/encoding-iterations', {
        method: 'POST',
        body: JSON.stringify({ base_payload_id: selectedEncodingBaseId }),
      })
      setActiveEncodingTask({ id: task.id, status: task.status, candidates: [] })
      messageApi.info('编码任务已进入队列，不会向任何目标发包')
    } catch (error) {
      setEncodingGenerating(false)
      messageApi.error(error instanceof Error ? error.message : '创建编码任务失败')
    }
  }

  const startPoolItem = async (item: IterationPoolItem) => {
    const isSemantic = item.agent === 'semantic'
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
        body: JSON.stringify({}),
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

  const techniqueNameById = (id: string) => kbTechniques.find((technique) => technique.technique_id === id)?.name || id
  const directionsByContent = new Map([...candidates, ...encodingCandidates].map((candidate) => [candidate.content, { techniques: candidate.technique_ids, next: candidate.next_directions }]))
  const candidatePayloadBlock = (label: string, content: string) => <div className="candidate-payload-block">
    <div className="candidate-content-heading"><Text type="secondary">{label}</Text><Button className="candidate-copy-button" type="text" size="small" icon={<CopyOutlined />} aria-label={`复制${label}`} title={`复制${label}`} onClick={(event) => { event.stopPropagation(); void copyCandidatePayload(content) }} /></div>
    <pre className="candidate-content">{content}</pre>{directionsByContent.has(content) && iterationDirections(directionsByContent.get(content)?.techniques, directionsByContent.get(content)?.next)}
  </div>
  const iterationDirections = (techniques: string[] = [], next: IterationDirection[] = []) => <div className="iteration-directions">
    <div><Text type="secondary">本条使用绕过手法</Text><div className="direction-tags">{techniques.length ? techniques.map((id) => <Tag color="blue" key={id}>{techniqueNameById(id)}</Tag>) : <Text type="secondary">暂无</Text>}</div></div>
    <div><Text type="secondary">下一轮 AI 思考方向</Text><div className="direction-tags">{next.length ? next.map((direction) => <Tag color="cyan" key={direction.id} title={direction.reason}>{direction.label}</Tag>) : <Text type="secondary">暂无可用方向</Text>}</div>{next.length > 0 && <Text type="secondary" className="direction-reason">{next.map((direction) => `${direction.label}：${direction.reason}`).join('；')}</Text>}</div>
  </div>

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

  const startCrossPoolItem = async (item: CrossPoolItem) => {
    setCrossPool((items) => items.map((current) => current.id === item.id
      ? { ...current, status: 'started' as const, task_status: 'queued' as const, task_error: null }
      : current))
    setCrossGenerating(true)
    try {
      const task = await api<CrossTask>(`/iteration-pools/cross/${item.id}/start`, {
        method: 'POST',
        body: JSON.stringify({}),
      })
      setActiveCrossTask({ ...task, candidates: [] })
      setCrossGenerating(['queued', 'running'].includes(task.status))
      await loadData()
      if (task.status === 'failed') {
        messageApi.error(task.error_message || '正向交叉任务失败，可在待迭代池中直接重试')
      } else {
        messageApi.info('正向交叉任务已启动，不会向任何目标发包')
      }
    } catch (error) {
      setCrossGenerating(false)
      await loadData()
      messageApi.error(error instanceof Error ? error.message : '启动待迭代池条目失败')
    }
  }

  const removeCrossPoolItem = async (item: CrossPoolItem) => {
    try {
      await api<void>(`/iteration-pools/cross/${item.id}`, { method: 'DELETE' })
      await loadData()
      messageApi.success('条目已移出正向交叉待迭代池')
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '移出待迭代池失败')
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
        techniqueCount: dashboardSummary.technique_count,
        bypassLibraryCount: dashboardSummary.bypass_library_count,
        blockLibraryCount: dashboardSummary.block_library_count,
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
      techniqueCount: 0,
      bypassLibraryCount: 0,
      blockLibraryCount: 0,
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

  const dashboardAgentRows = [
    { key: 'semantic', label: '语义迭代 Agent', color: 'blue', ...dashboardMetrics.agents.semantic },
    { key: 'encoding', label: '编码绕过 Agent', color: 'cyan', ...dashboardMetrics.agents.encoding },
    { key: 'cross', label: '正向交叉迭代', color: 'purple', ...dashboardMetrics.agents.cross },
  ]
  const dashboardAgentColumns = [
    { title: '处理单元', dataIndex: 'label', key: 'label', render: (label: string, row: { color: string }) => <Tag color={row.color}>{label}</Tag> },
    { title: '待测试', dataIndex: 'pending', key: 'pending', width: 90 },
    { title: '成功', dataIndex: 'success', key: 'success', width: 80, render: (value: number) => <Text type="success">{value}</Text> },
    { title: '失败', dataIndex: 'failed', key: 'failed', width: 90, render: (value: number) => <Text type={value ? 'danger' : 'secondary'}>{value}</Text> },
    { title: '有效率', dataIndex: 'rate', key: 'rate', width: 120, render: (value: number | null) => value === null ? <Text type="secondary">暂无闭环数据</Text> : <Text strong>{value.toFixed(1)}%</Text> },
  ]

  const dashboardWorkspace = workspace === 'dashboard' && <section className="workspace-card dashboard-workspace">
    <div className="dashboard-heading">
      <div>
        <Title level={4}>项目仪表盘</Title>
        <Text type="secondary">Payload 迭代闭环与自动验证状态总览</Text>
      </div>
      <Tag color="blue">本地工作台</Tag>
    </div>

    <div className="dashboard-kpi-grid">
      <Card className="dashboard-kpi-card" size="small"><Statistic title="正式 Payload" value={dashboardMetrics.payloadCount} suffix="条" prefix={<DatabaseOutlined />} /></Card>
      <Card className="dashboard-kpi-card" size="small"><Statistic title="语义待测试" value={dashboardMetrics.agents.semantic.pending} suffix="条" prefix={<ApiOutlined />} /></Card>
      <Card className="dashboard-kpi-card" size="small"><Statistic title="编码待测试" value={dashboardMetrics.agents.encoding.pending} suffix="条" prefix={<CodeOutlined />} /></Card>
      <Card className="dashboard-kpi-card" size="small"><Statistic title="正向交叉待测试" value={dashboardMetrics.agents.cross.pending} suffix="条" prefix={<ApartmentOutlined />} /></Card>
      <Card className="dashboard-kpi-card" size="small"><Statistic title="知识库技巧" value={dashboardMetrics.techniqueCount} suffix="条" prefix={<BookOutlined />} /></Card>
      <Card className="dashboard-kpi-card" size="small"><Statistic title="bypass 库" value={dashboardMetrics.bypassLibraryCount} suffix="条" prefix={<SafetyCertificateOutlined />} /></Card>
      <Card className="dashboard-kpi-card" size="small"><Statistic title="block 库" value={dashboardMetrics.blockLibraryCount} suffix="条" prefix={<StopOutlined />} /></Card>
    </div>

    <div className="dashboard-panel dashboard-flow-panel">
      <div className="dashboard-panel-heading"><div><Title level={5}>迭代流程</Title><Text type="secondary">Payload 迭代与验证闭环流程</Text></div><Tag color="blue">闭环流程</Tag></div>
      <img className="dashboard-flow-image" src="/iteration-flow.png" alt="迭代流程" />
    </div>

    <div className="dashboard-main-grid">
      <div className="dashboard-side-stack">
        <div className="dashboard-panel dashboard-rate-panel">
          <div className="dashboard-panel-heading"><div><Title level={5}>迭代有效率</Title><Text type="secondary">已闭环候选（bypass + block）中的成功率</Text></div></div>
          <div className="dashboard-rate-content">
            {dashboardMetrics.rate === null ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无闭环数据" /> : <><Progress type="circle" percent={dashboardMetrics.rate} size={132} strokeColor="#1677ff" format={(percent) => `${percent?.toFixed(1)}%`} /><div className="dashboard-rate-meta"><Text strong>{dashboardMetrics.success} 条成功</Text><Text type="secondary">/ {dashboardMetrics.completed} 条已闭环</Text><Text type="secondary">待测试 {dashboardMetrics.pending} 条</Text></div></>}
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
      <div className="dashboard-panel-heading"><div><Title level={5}>Agent 状态汇总</Title><Text type="secondary">基于自动验证结果（bypass 库 / block 库 / 待检验）统计</Text></div></div>
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
      { key: 'waf', icon: <SafetyCertificateOutlined />, label: '检验记录' },
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
          label: <div className="payload-card-label"><div><Text strong code>{payload.content}</Text><div className="payload-card-meta"><Tag color="orange">{payload.severity}</Tag><Tag color="green">可执行</Tag><Tag color="geekblue">{payload.delivery}</Tag></div></div><div className="payload-card-actions"><Button type="link" onClick={(event) => { event.stopPropagation(); void addToIterationPool('semantic', payload) }}>加入语义待迭代池</Button>{['command-injection', 'sql-injection', 'xss'].includes(payload.vulnerability) && <Button type="link" onClick={(event) => { event.stopPropagation(); void addToIterationPool('encoding', payload) }}>加入编码待迭代池</Button>}<Button type="link" onClick={(event) => { event.stopPropagation(); void addToCrossSources(payload) }}>加入正向交叉迭代</Button><Button type="link" onClick={(event) => { event.stopPropagation(); beginEdit(payload) }}>修改</Button><Popconfirm title="删除该条目？" onConfirm={() => void deletePayload(payload)}><Button danger type="link" onClick={(event) => event.stopPropagation()}>删除</Button></Popconfirm></div></div>,
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
    () => candidates.filter((candidate) => {
      // 待测试队列只显示「等待检验」：无检验任务（不可验证/关闭自动检验）仍显示；
      // 已有检验任务时，只有 waiting 状态留在队列（queued/running/completed/failed 离开）。
      if (['archived', 'rejected'].includes(candidate.status)) return false
      return candidate.verification_status == null || candidate.verification_status === 'waiting'
    }),
    [candidates],
  )
  const semanticPendingPool = retryablePoolItems(semanticPool)
  const semanticStartedPool = semanticPool.filter((item) => item.status === 'started' && ['queued', 'running', 'unknown'].includes(item.task_status || 'unknown'))
  const encodingPendingPool = retryablePoolItems(encodingPool)
  const encodingStartedPool = encodingPool.filter((item) => item.status === 'started' && ['queued', 'running', 'unknown'].includes(item.task_status || 'unknown'))
  const crossPendingPool = crossPool.filter((item) => item.status === 'pending')
  const crossStartedPool = crossPool.filter((item) => item.status === 'started' && ['queued', 'running', 'unknown'].includes(item.task_status || 'unknown'))
  const renderPoolItems = (items: IterationPoolItem[]) => items.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无待迭代条目" /> : <Collapse className="candidate-accordion" bordered={false} items={items.map((item) => ({
    key: item.id,
    label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong className="candidate-title-payload">{item.snapshot.content}</Text><div className="candidate-card-meta"><Tag color={vulnerabilityDefinitions[item.snapshot.vulnerability].tagColor}>{vulnerabilityDefinitions[item.snapshot.vulnerability].label}</Tag><Tag>{item.snapshot.target}</Tag><Tag color="geekblue">{item.snapshot.delivery}</Tag></div></div></div>,
    children: <div className="candidate-detail"><Text type="secondary">快照 Payload</Text><pre className="candidate-content">{item.snapshot.content}</pre>{item.task_status === 'failed' && <Alert type="error" showIcon title="上次迭代失败，可直接重试" description={item.task_error || '模型调用或候选校验失败'} />}{item.task_status === 'completed' && <Alert type="success" showIcon title="上次迭代已完成" description="原候选已保留，可从同一快照继续创建新一轮任务。" />}<Space><Button type="primary" size="small" onClick={() => void startPoolItem(item)}>{item.task_status === 'completed' ? '再次迭代' : item.task_status === 'failed' ? '重新迭代' : '开始迭代'}</Button><Popconfirm title="移出待迭代池？" description="该快照会被删除，不会影响原始 Payload。" onConfirm={() => void removePoolItem(item)}><Button danger size="small">移出池</Button></Popconfirm></Space></div>,
  }))} />
  const renderCrossPoolItems = (items: CrossPoolItem[]) => items.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无待交叉条目" /> : <Collapse className="candidate-accordion" bordered={false} items={items.map((item) => ({
    key: item.id,
    label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong className="candidate-title-payload">{item.source.content}</Text><div className="candidate-card-meta"><Tag color={vulnerabilityDefinitions[item.source.vulnerability].tagColor}>{vulnerabilityDefinitions[item.source.vulnerability].label}</Tag><Tag>{item.source.target}</Tag><Tag color="geekblue">{item.source.delivery}</Tag>{item.source.rule_labels.map((label) => <Tag key={label}>{label}</Tag>)}</div></div></div>,
    children: <div className="candidate-detail"><Text type="secondary">待交叉语义 Payload</Text><pre className="candidate-content">{item.source.content}</pre>{item.task_status === 'failed' && <Alert type="error" showIcon title="上次正向交叉失败，可直接重试" description={item.task_error || '模型调用或候选校验失败'} />}{item.task_status === 'completed' && <Alert type="success" showIcon title="上次正向交叉已完成" description="原候选已保留，可从同一来源继续创建新一轮任务。" />}<Space><Button type="primary" size="small" onClick={() => void startCrossPoolItem(item)}>{item.task_status === 'completed' ? '再次交叉' : item.task_status === 'failed' ? '重新交叉' : '开始交叉'}</Button><Popconfirm title="移出待交叉池？" description="仅移出池子，不影响 cross_source。" onConfirm={() => void removeCrossPoolItem(item)}><Button danger size="small">移出池</Button></Popconfirm></Space></div>,
  }))} />
  const agentWorkbench = workspace === 'agent' && <div className="agent-workbench">
    {visibleCandidates.some((candidate) => candidate.next_directions?.length) && <Card size="small" className="workbench-card" title="下一轮 AI 思考方向"><Space orientation="vertical" size="small">{visibleCandidates.filter((candidate) => candidate.next_directions?.length).map((candidate) => <div key={candidate.id}><Text strong className="candidate-title-payload">{candidate.content}</Text>{iterationDirections(candidate.technique_ids, candidate.next_directions)}</div>)}</Space></Card>}
    <div className="agent-grid">
      <Card className="workbench-card" title={<Space><ApiOutlined />语义迭代任务</Space>}>
        <Form layout="vertical">
          <div className="pool-heading"><Text strong>待迭代池</Text><Tag color="blue">{semanticPendingPool.length} 条</Tag></div>
          {renderPoolItems(semanticPendingPool)}
        </Form>
      </Card>
      <Card className="workbench-card" title="进行中任务">
        {semanticStartedPool.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无进行中任务" /> : <div className="pool-started-list">{semanticStartedPool.map((item) => <div className="pool-started-item" key={item.id}><Text strong className="candidate-title-payload">{item.snapshot.content}</Text><div><Tag color={item.task_status === 'completed' ? 'green' : item.task_status === 'failed' ? 'red' : 'blue'}>{item.task_status || 'queued'}</Tag></div></div>)}</div>}
        {activeTask && <div className="task-status"><Tag color={activeTask.status === 'completed' ? 'green' : activeTask.status === 'failed' ? 'red' : 'blue'}>{activeTask.status}</Tag>{activeTask.status === 'failed' && <Alert type="error" title={activeTask.error_message || '生成失败'} />}</div>}
      </Card>
    </div>
    <div className="queue-heading"><Title level={5}>待测试队列</Title><Tag color="blue">{visibleCandidates.length} 条</Tag></div>
    {visibleCandidates.length === 0 ? <Card className="empty-card" variant="borderless"><Empty description="暂无待测试候选" /></Card> : <Collapse className="candidate-accordion" accordion bordered={false} activeKey={expandedCandidate ? [expandedCandidate] : []} onChange={(key) => setExpandedCandidate(Array.isArray(key) ? key[0] || null : key || null)} items={visibleCandidates.map((candidate) => ({
      key: candidate.id,
      label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong className="candidate-title-payload">{candidate.content}</Text><div className="candidate-card-meta"><Tag color="blue">{candidate.base_target}</Tag><Tag color="geekblue">{candidate.delivery}</Tag>{candidate.rule_labels.map((label) => <Tag key={label}>{label}</Tag>)}{verificationStatusTag(candidate.verification_status)}</div></div><div className="candidate-card-actions" onClick={(event) => event.stopPropagation()}><Popconfirm title="删除该候选条目？" description="删除后无法恢复，且不会影响基础 Payload。" onConfirm={() => void deleteCandidate(candidate)}><Button danger type="link" size="small">删除</Button></Popconfirm></div></div>,
      children: <div className="candidate-detail">{candidatePayloadBlock('候选 Payload', candidate.content)}<Paragraph type="secondary">{candidate.explanation}</Paragraph></div>,
    }))} />}
    {pageControl('candidates')}
  </div>

  const agentWorkspace = <section className="workspace-card agent-workspace">{agentWorkbench}</section>

  const visibleEncodingCandidates = encodingCandidates.filter((candidate) => {
    if (candidate.status === 'archived') return false
    return candidate.verification_status == null || candidate.verification_status === 'waiting'
  })
  const encodingWorkbench = workspace === 'encoding' && <div className="agent-workbench">
    {visibleEncodingCandidates.some((candidate) => candidate.next_directions?.length) && <Card size="small" className="workbench-card" title="下一轮 AI 思考方向"><Space orientation="vertical" size="small">{visibleEncodingCandidates.filter((candidate) => candidate.next_directions?.length).map((candidate) => <div key={candidate.id}><Text strong className="candidate-title-payload">{candidate.content}</Text>{iterationDirections(candidate.technique_ids, candidate.next_directions)}</div>)}</Space></Card>}
    <div className="agent-grid">
      <Card className="workbench-card" title={<Space><CodeOutlined />编码绕过迭代任务</Space>}>
        <Form layout="vertical">
          <div className="pool-heading"><Text strong>待迭代池</Text><Tag color="blue">{encodingPendingPool.length} 条</Tag></div>
          {renderPoolItems(encodingPendingPool)}
        </Form>
      </Card>
      <Card className="workbench-card" title="进行中任务">
        {encodingStartedPool.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无进行中任务" /> : <div className="pool-started-list">{encodingStartedPool.map((item) => <div className="pool-started-item" key={item.id}><Text strong className="candidate-title-payload">{item.snapshot.content}</Text><div><Tag color={item.task_status === 'completed' ? 'green' : item.task_status === 'failed' ? 'red' : 'blue'}>{item.task_status || 'queued'}</Tag></div></div>)}</div>}
        {activeEncodingTask && <div className="task-status"><Tag color={activeEncodingTask.status === 'completed' ? 'green' : activeEncodingTask.status === 'failed' ? 'red' : 'blue'}>{activeEncodingTask.status}</Tag>{activeEncodingTask.status === 'failed' && <Alert type="error" title={activeEncodingTask.error_message || '编码生成失败'} />}</div>}
      </Card>
    </div>
    <div className="queue-heading"><Title level={5}>待测试队列</Title><Tag color="blue">{visibleEncodingCandidates.length} 条</Tag></div>
    {visibleEncodingCandidates.length === 0 ? <Card className="empty-card" variant="borderless"><Empty description="暂无编码候选" /></Card> : <Collapse className="candidate-accordion" accordion bordered={false} activeKey={expandedEncodingCandidate ? [expandedEncodingCandidate] : []} onChange={(key) => setExpandedEncodingCandidate(Array.isArray(key) ? key[0] || null : key || null)} items={visibleEncodingCandidates.map((candidate) => ({
      key: candidate.id,
      label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong className="candidate-title-payload">{candidate.content}</Text><div className="candidate-card-meta"><Tag color="blue">{candidate.base_target}</Tag><Tag color="geekblue">{candidate.delivery}</Tag>{candidate.origin === 'semantic_boundary_migration' && <Tag color="orange">历史迁移</Tag>}{candidate.rule_labels.map((label) => <Tag key={label}>{label}</Tag>)}{verificationStatusTag(candidate.verification_status)}</div></div><div className="candidate-card-actions" onClick={(event) => event.stopPropagation()}><Popconfirm title="删除该编码候选？" description="删除后无法恢复，且不会影响基础 Payload。" onConfirm={() => void deleteEncodingCandidate(candidate)}><Button danger type="link" size="small">删除</Button></Popconfirm></div></div>,
      children: <div className="candidate-detail">{candidatePayloadBlock('编码后 Payload', candidate.content)}{candidate.origin === 'semantic_boundary_migration' && <Alert type="warning" showIcon title="历史语义边界迁移" description={candidate.migration_note || '该候选来自旧版语义队列，未按新版编码重放器生成，请人工复核其解释前提。'} />}<div className="encoding-path"><Text strong>编码链：</Text><span>{candidate.encoding_chain.map((step) => `${encodingTypeLabels[step.type] || step.type}（${encodingModeLabel(step.mode, step.submode)}）`).join(' → ')}</span></div><div className="encoding-path"><Text strong>预期解码路径：</Text><span>{candidate.decode_path.map((step) => encodingTypeLabels[step] || step).join(' → ')}</span></div>{encodingPrerequisites(candidate.encoding_chain) && <Paragraph type="secondary">{encodingPrerequisites(candidate.encoding_chain)}</Paragraph>}<Paragraph type="secondary">{candidate.explanation}</Paragraph></div>,
    }))} />}
    {pageControl('encodingCandidates')}
  </div>

  const encodingWorkspace = <section className="workspace-card agent-workspace">{encodingWorkbench}</section>

  const visibleCrossCandidates = crossCandidates.filter((candidate) => {
    return candidate.verification_status == null || candidate.verification_status === 'waiting'
  })
  const crossWorkspace = workspace === 'cross' && <section className="workspace-card agent-workspace"><div className="agent-workbench">
    <div className="agent-grid">
      <Card className="workbench-card" title={<Space><ApartmentOutlined />正向交叉迭代任务</Space>}>
        <Form layout="vertical">
          <div className="pool-heading"><Text strong>待迭代池</Text><Tag color="blue">{crossPendingPool.length} 条</Tag></div>
          {renderCrossPoolItems(crossPendingPool)}
        </Form>
      </Card>
      <Card className="workbench-card" title="进行中任务">
        {crossStartedPool.length === 0 ? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无进行中任务" /> : <div className="pool-started-list">{crossStartedPool.map((item) => <div className="pool-started-item" key={item.id}><Text strong className="candidate-title-payload">{item.source.content}</Text><div><Tag color={item.task_status === 'completed' ? 'green' : item.task_status === 'failed' ? 'red' : 'blue'}>{item.task_status || 'queued'}</Tag></div></div>)}</div>}
        {activeCrossTask && <div className="task-status"><Tag color={activeCrossTask.status === 'completed' ? 'green' : activeCrossTask.status === 'failed' ? 'red' : 'blue'}>{activeCrossTask.status}</Tag>{activeCrossTask.status === 'failed' && <Alert type="error" title={activeCrossTask.error_message || '正向交叉生成失败'} />}</div>}
      </Card>
    </div>
    <div className="queue-heading"><Title level={5}>待测试队列</Title><Tag color="blue">{visibleCrossCandidates.length} 条</Tag></div>
    {visibleCrossCandidates.length === 0 ? <Card className="empty-card" variant="borderless"><Empty description="暂无正向交叉候选" /></Card> : <Collapse className="candidate-accordion" accordion bordered={false} activeKey={expandedCrossCandidate ? [expandedCrossCandidate] : []} onChange={(key) => setExpandedCrossCandidate(Array.isArray(key) ? key[0] || null : key || null)} items={visibleCrossCandidates.map((candidate) => ({
      key: candidate.id,
      label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong className="candidate-title-payload">{candidate.content}</Text><div className="candidate-card-meta"><Tag color="blue">{candidate.source_target}</Tag><Tag color="geekblue">{candidate.source_delivery}</Tag>{candidate.semantic_rule_labels.map((label) => <Tag key={`semantic-${label}`}>{label}</Tag>)}{candidate.rule_labels.map((label) => <Tag color="purple" key={`encoding-${label}`}>{label}</Tag>)}{verificationStatusTag(candidate.verification_status)}</div></div><div className="candidate-card-actions" onClick={(event) => event.stopPropagation()}><Popconfirm title="删除该正向交叉候选？" description="候选会删除，但该编码链会保留为历史记录，不会重复生成。" onConfirm={() => void deleteCrossCandidate(candidate)}><Button danger type="link" size="small">删除</Button></Popconfirm></div></div>,
      children: <div className="candidate-detail"><div className="candidate-payload-block"><div className="candidate-content-heading"><Text type="secondary">语义来源 Payload</Text></div><pre className="candidate-content">{candidate.semantic_content}</pre></div>{candidatePayloadBlock('编码后 Payload', candidate.content)}<div className="encoding-path"><Text strong>编码链：</Text><span>{candidate.encoding_chain.map((step) => `${encodingTypeLabels[step.type] || step.type}（${encodingModeLabel(step.mode, step.submode)}）`).join(' → ')}</span></div><div className="encoding-path"><Text strong>预期解码路径：</Text><span>{candidate.decode_path.map((step) => encodingTypeLabels[step] || step).join(' → ')}</span></div></div>,
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
  const libraryDetail = (entry: BypassLibraryEntry) => <div className="candidate-detail">
    <Text type="secondary">Payload 内容</Text><pre className="candidate-content">{entry.content}</pre>
    <Paragraph type="secondary">判定依据：{entry.rationale || '无'}</Paragraph>
    {(entry.techniques || []).length > 0 && <><Text type="secondary">绕过技法（按使用顺序）</Text><div className="encoding-path"><span>{entry.techniques.map((t) => `${t.name}（${t.id}）`).join(' → ')}</span></div></>}
    {(entry.encoding_chain || []).length > 0 && <><Text type="secondary">编码形式（按使用顺序）</Text><div className="encoding-path"><span>{entry.encoding_chain.map((step) => `${encodingTypeLabels[step.type] || step.type}（${encodingModeLabel(step.mode, step.submode)}）`).join(' → ')}</span></div></>}
    <Text type="secondary">来源链路</Text><pre className="candidate-content">{JSON.stringify(entry.provenance, null, 2)}</pre>
  </div>
  const exportBypassCsv = async (vulnerability: VulnerabilityKey) => {
    // 导出需覆盖该漏洞类型的全量数据，因此直接从后端拉全量（不过页）。
    let entries: BypassLibraryEntry[]
    try {
      entries = await api<BypassLibraryEntry[]>(`/bypass-library?vulnerability=${encodeURIComponent(vulnerability)}`)
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '导出失败，无法读取 bypass 数据')
      return
    }
    if (entries.length === 0) {
      messageApi.warning('该漏洞类型暂无 bypass 记录可导出')
      return
    }
    const escapeCell = (value: string) => {
      const text = value ?? ''
      return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
    }
    const header = ['内容', '来源', '漏洞类型', '靶场', '投递方式', '绕过技法', '编码形式', '置信度', '判定依据']
    const rows = entries.map((entry) => [
      entry.content,
      verificationAgentLabels[entry.source_agent],
      vulnerabilityDefinitions[entry.vulnerability].label,
      entry.target_key,
      entry.delivery,
      (entry.techniques || []).map((t) => `${t.name}（${t.id}）`).join(' → '),
      (entry.encoding_chain || []).map((step) => `${encodingTypeLabels[step.type] || step.type}（${encodingModeLabel(step.mode, step.submode)}）`).join(' → '),
      entry.confidence != null ? `${(entry.confidence * 100).toFixed(0)}%` : '',
      entry.rationale || '',
    ])
    const csv = '﻿' + [header, ...rows].map((row) => row.map(escapeCell).join(',')).join('\r\n')
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${vulnerabilityDefinitions[vulnerability].label}.csv`
    link.click()
    URL.revokeObjectURL(url)
    messageApi.success(`已导出 ${entries.length} 条到 ${vulnerabilityDefinitions[vulnerability].label}.csv`)
  }
  const bypassVulnTabContent = (vulnerability: VulnerabilityKey) => {
    const entries = bypassLibrary.filter((entry) => entry.vulnerability === vulnerability)
    const definition = vulnerabilityDefinitions[vulnerability]
    const total = bypassVulnTotal[vulnerability] || entries.length
    const currentPage = bypassVulnPage[vulnerability] || 1
    return <div className="payload-list-layout">
      <div className="panel-heading payload-list-heading"><Space><Title level={5}>{definition.label}</Title><Tag color={definition.tagColor}>{total} 条</Tag></Space><Button size="small" type="primary" icon={<DownloadOutlined />} onClick={() => void exportBypassCsv(vulnerability)}>导出 CSV</Button></div>
      {entries.length === 0 ? <Card className="empty-card" variant="borderless"><Empty description="暂无 bypass 结果" /></Card> : <Collapse className="candidate-accordion" accordion bordered={false} items={entries.map((entry) => ({ key: entry.id, label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong className="candidate-title-payload">{entry.content}</Text><div className="candidate-card-meta"><Tag color={entry.source_agent === 'cross' ? 'purple' : entry.source_agent === 'encoding' ? 'cyan' : 'blue'}>{verificationAgentLabels[entry.source_agent]}</Tag><Tag color={vulnerabilityDefinitions[entry.vulnerability].tagColor}>{vulnerabilityDefinitions[entry.vulnerability].label}</Tag><Tag color="green">绕过成功</Tag><Tag color="green">验证成功</Tag></div></div></div>, children: libraryDetail(entry) }))} />}
      {total > PAGE_SIZE ? <Pagination
        className="list-pagination"
        size="small"
        current={currentPage}
        pageSize={PAGE_SIZE}
        total={total}
        showSizeChanger={false}
        onChange={(next) => setBypassVulnPage((current) => ({ ...current, [vulnerability]: next }))}
      /> : null}
    </div>
  }
  const bypassLibraryTabs: TabsProps['items'] = vulnerabilityKeys.map((key) => ({ key, label: <span className="tab-label">{vulnerabilityDefinitions[key].icon}{vulnerabilityDefinitions[key].label}</span>, children: bypassVulnTabContent(key) }))
  const bypassLibraryWorkspace = workspace === 'bypass-library' && <section className="workspace-card payload-workspace"><div className="samples-workspace">
    <div className="panel-heading"><Space><SafetyCertificateOutlined /><Title level={5}>bypass 库</Title><Tag color="green">{dashboardMetrics.bypassLibraryCount} 条</Tag></Space></div>
    <Tabs activeKey={bypassVulnTab} onChange={(key) => setBypassVulnTab(key as VulnerabilityKey)} items={bypassLibraryTabs} />
  </div></section>
  const blockVulnTabContent = (vulnerability: VulnerabilityKey) => {
    const entries = blockLibrary.filter((entry) => entry.vulnerability === vulnerability)
    const definition = vulnerabilityDefinitions[vulnerability]
    const total = blockVulnTotal[vulnerability] || entries.length
    const currentPage = blockVulnPage[vulnerability] || 1
    return <div className="payload-list-layout">
      <div className="panel-heading payload-list-heading"><Space><Title level={5}>{definition.label}</Title><Tag color={definition.tagColor}>{total} 条</Tag></Space></div>
      {entries.length === 0 ? <Card className="empty-card" variant="borderless"><Empty description="暂无 block 结果" /></Card> : <Collapse className="candidate-accordion" accordion bordered={false} items={entries.map((entry) => ({ key: entry.id, label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong className="candidate-title-payload">{entry.content}</Text><div className="candidate-card-meta"><Tag color={entry.source_agent === 'cross' ? 'purple' : entry.source_agent === 'encoding' ? 'cyan' : 'blue'}>{verificationAgentLabels[entry.source_agent]}</Tag><Tag color={vulnerabilityDefinitions[entry.vulnerability].tagColor}>{vulnerabilityDefinitions[entry.vulnerability].label}</Tag><Tag color={failureStageLabels[entry.failure_stage].color}>{failureStageLabels[entry.failure_stage].label}</Tag></div></div></div>, children: libraryDetail(entry) }))} />}
      {total > PAGE_SIZE ? <Pagination
        className="list-pagination"
        size="small"
        current={currentPage}
        pageSize={PAGE_SIZE}
        total={total}
        showSizeChanger={false}
        onChange={(next) => setBlockVulnPage((current) => ({ ...current, [vulnerability]: next }))}
      /> : null}
    </div>
  }
  const blockLibraryTabs: TabsProps['items'] = vulnerabilityKeys.map((key) => ({ key, label: <span className="tab-label">{vulnerabilityDefinitions[key].icon}{vulnerabilityDefinitions[key].label}</span>, children: blockVulnTabContent(key) }))
  const blockLibraryWorkspace = workspace === 'block-library' && <section className="workspace-card payload-workspace"><div className="samples-workspace">
    <div className="panel-heading"><Space><StopOutlined /><Title level={5}>block 库</Title><Tag color="red">{dashboardMetrics.blockLibraryCount} 条</Tag></Space></div>
    <Tabs activeKey={blockVulnTab} onChange={(key) => setBlockVulnTab(key as VulnerabilityKey)} items={blockLibraryTabs} />
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
    <div className="panel-heading"><Space><QuestionCircleOutlined /><Title level={5}>待人工验证</Title><Tag color="orange">{totals.unverifiedLibrary} 条</Tag></Space></div>
    {unverifiedLibrary.length === 0 ? <Card className="empty-card" variant="borderless"><Empty description="暂无待人工验证结果" /></Card> : <Collapse className="candidate-accordion" accordion bordered={false} items={unverifiedLibrary.map((entry) => ({ key: entry.id, label: <div className="candidate-card-label"><div className="candidate-card-title"><Text strong className="candidate-title-payload">{entry.content}</Text><div className="candidate-card-meta"><Tag color={entry.source_agent === 'cross' ? 'purple' : entry.source_agent === 'encoding' ? 'cyan' : 'blue'}>{verificationAgentLabels[entry.source_agent]}</Tag><Tag color={vulnerabilityDefinitions[entry.vulnerability].tagColor}>{vulnerabilityDefinitions[entry.vulnerability].label}</Tag><Tag color="orange">待人工验证</Tag></div></div></div>, children: unverifiedDetail(entry) }))} />}
    {pageControl('unverifiedLibrary')}
  </div></section>


  const verdictStatusTag = (job: VerificationJob) => {
    if (job.status !== 'completed') {
      const config: Record<string, [string, string]> = {
        waiting: ['default', '等待检验'],
        queued: ['blue', '排队检验'],
        running: ['processing', '检验中'],
        failed: ['red', '检验失败'],
      }
      const [color, label] = config[job.status] || ['default', job.status]
      return <Tag color={color}>{label}</Tag>
    }
    if (job.bypass_verdict === 'block') return <Tag color="red">waf_block</Tag>
    if (job.bypass_verdict === 'error') return <Tag color="default">检验异常</Tag>
    if (job.execution_verdict === 'confirmed') return <Tag color="green">waf_bypass · 验证成功</Tag>
    if (job.execution_verdict === 'unverified') return <Tag color="blue">waf_bypass · 未验证</Tag>
    return <Tag color="orange">waf_bypass · 验证失败</Tag>
  }

  const verificationJobEvidence = (job: VerificationJob) => {
    const raw = job.raw_evidence as { evidence?: string } | null
    return raw?.evidence || job.error_message || ''
  }

  const wafWorkspace = workspace === 'waf' && <section className="workspace-card payload-workspace">
    <div className="panel-heading"><Space><SafetyCertificateOutlined /><Title level={5}>检验记录</Title><Tag color="blue">{verificationJobs.length} 条</Tag></Space></div>
    <Card className="workbench-card" title="最近检验记录" extra={<Button size="small" onClick={() => void loadVerificationJobs()}>刷新</Button>}>
      {verificationJobs.length === 0 ? <Empty description="暂无检验记录" /> : <Table<VerificationJob> className="payload-table" rowKey="id" size="small" pagination={{ pageSize: 8 }} dataSource={verificationJobs} columns={[
        { title: 'Payload 内容', dataIndex: 'payload_snapshot', key: 'payload', ellipsis: true, render: (content: string) => <Text code>{content}</Text> },
        { title: '漏洞', dataIndex: 'vulnerability', key: 'vulnerability', width: 110, render: (vulnerability: VulnerabilityKey) => <Tag color={vulnerabilityDefinitions[vulnerability].tagColor}>{vulnerabilityDefinitions[vulnerability].label}</Tag> },
        { title: '状态', key: 'verdict', width: 190, render: (_, job) => verdictStatusTag(job) },
        { title: '证据', key: 'evidence', ellipsis: true, render: (_, job) => <Text type="secondary">{verificationJobEvidence(job)}</Text> },
        { title: '时间', dataIndex: 'created_at', key: 'created_at', width: 180 },
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
    <div className="panel-heading"><Space><AimOutlined /><Title level={5}>靶场管理</Title><Tag color="blue">{verificationTargets.length} 个靶场</Tag></Space></div>
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
    { title: '状态', dataIndex: 'status', key: 'status', width: 100, render: (s: string) => {
      if (s === 'seed') return <Tag color="geekblue">主力</Tag>
      if (s === 'promoted') return <Tag color="green">已转正</Tag>
      if (s === 'frontier') return <Tag color="orange">待验证</Tag>
      if (s === 'retired') return <Tag color="default">已淘汰</Tag>
      return <Tag>{s}</Tag>
    } },
    { title: '成功次数', dataIndex: 'success_count', key: 'success_count', width: 100 },
    { title: '操作', key: 'action', width: 90, render: (_: unknown, record: KbTechnique) => (
      <Popconfirm title={record.status === 'retired' ? '启用该技法？' : '禁用该技法？'} description={record.status === 'retired' ? '恢复为 frontier，重新参与生成与穷举。' : '标记为 retired，不再参与生成、穷举与泛化。'} onConfirm={() => void toggleKbTechnique(record)}>
        <Button type="link" size="small" danger={record.status !== 'retired'}>{record.status === 'retired' ? '启用' : '禁用'}</Button>
      </Popconfirm>
    ) },
  ]
  const kbTechniqueGroup = (group: 'semantic' | 'encoding', vuln: string = 'all') => kbTechniques.filter((t) => t.group === group && (vuln === 'all' || t.vulnerability === vuln))
  const kbGroupStats = (group: 'semantic' | 'encoding') => kbStats?.[group] ?? { total: 0, promoted: 0 }
  const kbGroupHandover = (group: 'semantic' | 'encoding') => (kbHandover?.[group] ?? []).slice(0, 20)
  const kbImportArticle = async () => {
    if (!kbArticle.trim()) return
    setKbArticleImporting(true)
    try {
      await api<{ inserted: number; parsed: number }>('/kb-techniques/import', { method: 'POST', body: JSON.stringify({ content: kbArticle, source_name: `manual_${Date.now()}.md`, vulnerability: kbArticleVuln }) })
      messageApi.success('教材已保存为拓新燃料，将由拓新 Agent 在迭代收尾时生成新技法')
      setKbArticle('')
      setKbTechniques(await api<KbTechnique[]>('/kb-techniques'))
      setKbStats(await api<KbTechniqueStats>('/kb-techniques/stats'))
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '文章导入失败')
    } finally {
      setKbArticleImporting(false)
    }
  }
  const toggleKbTechnique = async (technique: KbTechnique) => {
    const disabled = technique.status === 'retired'
    try {
      await api<KbTechnique>(`/kb-techniques/${technique.id}`, { method: 'PATCH', body: JSON.stringify({ enabled: disabled }) })
      messageApi.success(disabled ? '技法已启用' : '技法已禁用')
      setKbTechniques(await api<KbTechnique[]>('/kb-techniques'))
      setKbStats(await api<KbTechniqueStats>('/kb-techniques/stats'))
    } catch (error) {
      messageApi.error(error instanceof Error ? error.message : '操作失败')
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
    <div className="panel-heading"><Space><BookOutlined /><Title level={5}>知识库管理</Title><Tag color="blue">{kbTechniques.length} 条技巧</Tag></Space></div>
    <Tabs defaultActiveKey="semantic" items={[
      { key: 'semantic', label: '语义绕过手法', children: kbVulnTabs('semantic', kbGroupHandover('semantic'), 'blue') },
      { key: 'encoding', label: '编码绕过手法', children: kbVulnTabs('encoding', kbGroupHandover('encoding'), 'cyan') },
      { key: 'article', label: '文章输入', children: <div className="samples-workspace">
        <Card className="workbench-card" size="small" title="教材文章输入">
          <Text type="secondary">粘贴教材文章并指定漏洞类型，作为拓新 Agent 的燃料（拓新时按漏洞类型读取，不直接提取入库）。</Text>
          <div style={{ marginTop: 12, marginBottom: 12 }}>
            <Text strong>漏洞类型：</Text>
            <Select style={{ width: 220, marginLeft: 8 }} value={kbArticleVuln} options={vulnerabilityKeys.map((key) => ({ value: key, label: vulnerabilityDefinitions[key].label }))} onChange={(key) => setKbArticleVuln(key as VulnerabilityKey)} />
          </div>
          <Input.TextArea rows={14} placeholder="在此粘贴教材文章…" value={kbArticle} onChange={(event) => setKbArticle(event.target.value)} style={{ marginBottom: 12 }} />
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
    waf: '检验记录',
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
