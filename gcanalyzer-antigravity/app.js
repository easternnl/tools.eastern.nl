/**
 * IBM J9 GC Log Analyzer - Core Application Logic
 * Implements completely client-side parsing, metrics computation, Chart.js visualization,
 * and AI diagnostics for verbosegc logs.
 */

// Global Application State
const state = {
  fileName: '',
  fileSize: 0,
  rawText: '',
  
  // Parsed Data
  jvmInfo: {
    gcPolicy: '-',
    maxHeapSize: '-',
    initialHeapSize: '-',
    gcthreads: '-',
    cpus: '-',
    os: '-',
    compressedRefs: '-',
    vmargs: []
  },
  gcEvents: [],     // All parsed GC events
  heapResizes: [],  // All heap resize events
  exclusiveStarts: [], // Exclusive VM access info
  afStarts: [],     // Allocation failures
  
  // Computed Metrics
  metrics: {
    totalGCTime: 0,
    totalCycles: 0,
    scavengeCount: 0,
    globalCount: 0,
    avgScavengePause: 0,
    avgGlobalPause: 0,
    maxPause: 0,
    maxPauseType: '',
    gcOverheadPct: 0,
    totalReclaimedBytes: 0,
    avgReclaimedBytes: 0,
    avgIntervalSec: 0,
    allocTotalBytes: 0,
    allocRateMbSec: 0
  },
  
  // UI Pagination State
  pagination: {
    currentPage: 1,
    pageSize: 15,
    filteredEvents: []
  },
  
  // Sorting State
  sorting: {
    field: 'id',
    ascending: true
  },
  
  // Theme State
  theme: 'dark'
};

// Chart.js Instances
let memoryChartInstance = null;
let gcBreakdownChartInstance = null;
let gcDurationChartInstance = null;
let reclaimedChartInstance = null;

// Initialize Lucide Icons & DOM Listeners
document.addEventListener('DOMContentLoaded', () => {
  // Initialize Lucide
  lucide.createIcons();
  
  // Setup theme
  initTheme();
  
  // Setup DOM Event Handlers
  setupFileUploader();
  setupNavigation();
  setupPagination();
  setupTableFilters();
  setupDrawerTabs();
});

/* ----------------------------------------------------
   1. THEME MANAGEMENT
---------------------------------------------------- */
function initTheme() {
  const toggleBtn = document.getElementById('theme-toggle');
  
  // Check system preference or default to dark
  const savedTheme = localStorage.getItem('gc-analyzer-theme') || 'dark';
  setTheme(savedTheme);
  
  toggleBtn.addEventListener('click', () => {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
  });
}

function setTheme(theme) {
  state.theme = theme;
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('gc-analyzer-theme', theme);
  
  // Update theme of active charts
  updateChartsTheme();
}

function updateChartsTheme() {
  const isLight = state.theme === 'light';
  const textColor = isLight ? '#475569' : '#94a3b8';
  const gridColor = isLight ? 'rgba(15, 23, 42, 0.06)' : 'rgba(255, 255, 255, 0.05)';
  
  const updateOpts = (chart) => {
    if (!chart) return;
    chart.options.scales.x.grid.color = gridColor;
    chart.options.scales.y.grid.color = gridColor;
    chart.options.scales.x.ticks.color = textColor;
    chart.options.scales.y.ticks.color = textColor;
    if (chart.options.scales.y1) {
      chart.options.scales.y1.grid.color = gridColor;
      chart.options.scales.y1.ticks.color = textColor;
    }
    if (chart.options.plugins.legend && chart.options.plugins.legend.labels) {
      chart.options.plugins.legend.labels.color = textColor;
    }
    chart.update();
  };
  
  updateOpts(memoryChartInstance);
  updateOpts(gcDurationChartInstance);
  updateOpts(reclaimedChartInstance);
}

/* ----------------------------------------------------
   2. FILE UPLOADER
---------------------------------------------------- */
function setupFileUploader() {
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  const filePreview = document.getElementById('file-preview-card');
  const fileNameDisplay = document.getElementById('file-name');
  const fileSizeDisplay = document.getElementById('file-size');
  const analyzeBtn = document.getElementById('analyze-btn');
  const newFileBtn = document.getElementById('new-file-btn');
  
  // Drag & drop handlers
  dropZone.addEventListener('click', () => fileInput.click());
  
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });
  
  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });
  
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  });
  
  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleFileSelected(e.target.files[0]);
    }
  });
  
  analyzeBtn.addEventListener('click', () => {
    if (state.rawText) {
      processLogData();
    }
  });
  
  newFileBtn.addEventListener('click', () => {
    // Reset state & show uploader
    document.getElementById('app-container').classList.add('hidden');
    document.getElementById('upload-screen').classList.remove('hidden');
    filePreview.classList.add('hidden');
    dropZone.classList.remove('hidden');
    fileInput.value = '';
    state.rawText = '';
  });
}

function handleFileSelected(file) {
  state.fileName = file.name;
  state.fileSize = file.size;
  
  const fileSizeMb = (file.size / (1024 * 1024)).toFixed(2);
  document.getElementById('file-name').innerText = file.name;
  document.getElementById('file-size').innerText = `${fileSizeMb} MB`;
  
  document.getElementById('drop-zone').classList.add('hidden');
  document.getElementById('file-preview-card').classList.remove('hidden');
  
  // Show loading screen while reading file
  showLoading('Reading file...', 'Buffering text content into memory...');
  
  const reader = new FileReader();
  reader.onload = (e) => {
    state.rawText = e.target.result;
    hideLoading();
  };
  reader.onerror = () => {
    alert('Failed to read file.');
    hideLoading();
  };
  reader.readAsText(file);
}

function showLoading(title, details) {
  document.getElementById('loading-screen').classList.remove('hidden');
  document.getElementById('loading-status').innerText = title;
  document.getElementById('loading-details').innerText = details;
  document.getElementById('loading-progress').style.width = '100%';
}

function hideLoading() {
  document.getElementById('loading-screen').classList.add('hidden');
}

/* ----------------------------------------------------
   3. HIGH PERFORMANCE REGEX PARSER
---------------------------------------------------- */
function processLogData() {
  showLoading('Parsing GC Log...', 'Running tokenizer on verbosegc elements...');
  
  // Use setTimeout to yield thread so loader displays
  setTimeout(() => {
    const startTime = performance.now();
    
    // Core Parse
    parseLogText(state.rawText);
    
    // Compute stats
    computeStats();
    
    // Update UI elements
    updateUI();
    
    // Draw charts
    initCharts();
    
    // Run diagnostics
    runDiagnostics();
    
    hideLoading();
    
    // Transition views
    document.getElementById('upload-screen').classList.add('hidden');
    document.getElementById('app-container').classList.remove('hidden');
    
    // Log performance
    console.log(`Parsed log in ${(performance.now() - startTime).toFixed(1)}ms. Total GC events: ${state.gcEvents.length}`);
  }, 100);
}

function parseLogText(text) {
  // Reset lists
  state.gcEvents = [];
  state.heapResizes = [];
  state.exclusiveStarts = [];
  state.afStarts = [];
  state.jvmInfo = {
    gcPolicy: '-',
    maxHeapSize: '-',
    initialHeapSize: '-',
    gcthreads: '-',
    cpus: '-',
    os: '-',
    compressedRefs: '-',
    vmargs: []
  };

  const tagRegex = /<(\/?[a-zA-Z0-9:-]+)([\s\S]*?)?(\/?)>/g;
  const attrRegex = /([a-zA-Z0-9:-]+)\s*=\s*"([^"]*)"/g;

  let match;
  const stack = [];
  
  // Parser Context
  let activeInitialized = false;
  let activeSystem = false;
  let activeVmargs = false;
  let activeGc = null;
  let activeOp = null;
  let activeExclusive = null;
  
  // Track slice indices to reconstruct raw XML block for each GC run
  let currentEventStartIndex = 0;
  
  // We will loop through tags
  while ((match = tagRegex.exec(text)) !== null) {
    const fullTag = match[0];
    let tagName = match[1];
    const attrString = match[2] || '';
    const isSelfClosing = match[3] === '/' || fullTag.endsWith('/>');
    const isClosing = tagName.startsWith('/');
    
    if (isClosing) {
      tagName = tagName.slice(1);
      
      // Match stack
      let foundIndex = -1;
      for (let i = stack.length - 1; i >= 0; i--) {
        if (stack[i].tagName === tagName) {
          foundIndex = i;
          break;
        }
      }
      
      if (foundIndex !== -1) {
        // Resolve nested connections
        for (let i = stack.length - 1; i >= foundIndex; i--) {
          const item = stack[i];
          
          if (item.tagName === 'mem-info') {
            const memInfo = item.data;
            const parent = stack[foundIndex - 1];
            if (parent) {
              if (parent.tagName === 'gc-start') {
                parent.data.memBefore = memInfo;
              } else if (parent.tagName === 'gc-end') {
                parent.data.memAfter = memInfo;
              }
            } else if (activeGc) {
              // Fallback
              if (!activeGc.memBefore) activeGc.memBefore = memInfo;
              else activeGc.memAfter = memInfo;
            }
          }
          
          if (item.tagName === 'gc-end') {
            // End of GC run, save the raw XML block!
            if (activeGc) {
              activeGc.rawXml = text.substring(currentEventStartIndex, match.index + fullTag.length);
              activeGc = null;
            }
          }
          
          if (item.tagName === 'exclusive-start') {
            activeExclusive = null;
          }
        }
        stack.splice(foundIndex);
      }
      
      if (tagName === 'initialized') activeInitialized = false;
      if (tagName === 'system') activeSystem = false;
      if (tagName === 'vmargs') activeVmargs = false;
      if (tagName === 'gc-op') activeOp = null;
      
      continue;
    }
    
    // Parse attributes
    const attrs = {};
    let attrMatch;
    attrRegex.lastIndex = 0;
    while ((attrMatch = attrRegex.exec(attrString)) !== null) {
      attrs[attrMatch[1]] = attrMatch[2];
    }
    
    // Handle tag start
    if (tagName === 'initialized') {
      activeInitialized = true;
      state.jvmInfo.timestamp = attrs.timestamp;
    } else if (tagName === 'attribute') {
      if (activeInitialized) {
        if (activeSystem) {
          if (attrs.name === 'physicalMemory') state.jvmInfo.physicalMemory = formatBytes(parseInt(attrs.value));
          if (attrs.name === 'numCPUs active') state.jvmInfo.cpus = attrs.value;
          if (attrs.name === 'os') state.jvmInfo.os = attrs.value;
        } else {
          if (attrs.name === 'gcPolicy') state.jvmInfo.gcPolicy = attrs.value;
          if (attrs.name === 'maxHeapSize') state.jvmInfo.maxHeapSize = formatBytes(parseInt(attrs.value));
          if (attrs.name === 'initialHeapSize') state.jvmInfo.initialHeapSize = formatBytes(parseInt(attrs.value));
          if (attrs.name === 'gcthreads') state.jvmInfo.gcthreads = attrs.value;
          if (attrs.name === 'compressedRefs') state.jvmInfo.compressedRefs = attrs.value;
        }
      }
    } else if (tagName === 'system') {
      activeSystem = true;
    } else if (tagName === 'vmargs') {
      activeVmargs = true;
    } else if (tagName === 'vmarg') {
      if (activeVmargs) {
        state.jvmInfo.vmargs.push(attrs.name);
      }
    } else if (tagName === 'exclusive-start') {
      currentEventStartIndex = match.index; // start capture here!
      activeExclusive = {
        id: attrs.id,
        timestamp: attrs.timestamp,
        intervalms: parseFloat(attrs.intervalms || 0),
        durationms: 0
      };
      state.exclusiveStarts.push(activeExclusive);
      if (!isSelfClosing) {
        stack.push({ tagName: 'exclusive-start', data: activeExclusive });
      }
    } else if (tagName === 'exclusive-end') {
      if (activeExclusive) {
        activeExclusive.durationms = parseFloat(attrs.durationms || 0);
      }
    } else if (tagName === 'af-start') {
      const af = {
        id: attrs.id,
        threadId: attrs.threadId,
        totalBytesRequested: parseInt(attrs.totalBytesRequested || 0),
        timestamp: attrs.timestamp,
        intervalms: parseFloat(attrs.intervalms || 0),
        type: attrs.type
      };
      state.afStarts.push(af);
    } else if (tagName === 'gc-start') {
      // If we didn't start capturing index at exclusive-start, start here
      if (stack.length === 0 || stack[stack.length-1].tagName !== 'exclusive-start') {
        currentEventStartIndex = match.index;
      }
      
      // Look up if we have an active allocation failure to hook up trigger
      let lastAf = state.afStarts[state.afStarts.length - 1];
      let bytesRequested = 0;
      let trigger = 'Allocation Failure';
      if (lastAf && Math.abs(new Date(attrs.timestamp) - new Date(lastAf.timestamp)) < 2000) {
        bytesRequested = lastAf.totalBytesRequested;
        trigger = `Alloc Failure (${lastAf.type})`;
      }
      
      activeGc = {
        id: attrs.id,
        type: attrs.type, // scavenge or global
        contextid: attrs.contextid,
        timestamp: attrs.timestamp,
        timeEpoch: new Date(attrs.timestamp).getTime(),
        durationms: 0,
        memBefore: null,
        memAfter: null,
        reclaimedBytes: 0,
        allocationRequest: bytesRequested,
        triggerReason: trigger,
        resizes: [],
        ops: [],
        cpuSystem: 0,
        cpuUser: 0,
        stalls: 0,
        activeThreads: 0,
        rawXml: ''
      };
      state.gcEvents.push(activeGc);
      stack.push({ tagName: 'gc-start', data: activeGc });
    } else if (tagName === 'mem-info') {
      const memInfo = {
        id: attrs.id,
        free: parseInt(attrs.free || 0),
        total: parseInt(attrs.total || 0),
        percent: parseInt(attrs.percent || 0),
        spaces: {}
      };
      stack.push({ tagName: 'mem-info', data: memInfo });
    } else if (tagName === 'mem') {
      const memDetails = {
        type: attrs.type,
        free: parseInt(attrs.free || 0),
        total: parseInt(attrs.total || 0),
        percent: parseInt(attrs.percent || 0),
        subSpaces: {}
      };
      
      const parent = stack[stack.length - 1];
      if (parent) {
        if (parent.tagName === 'mem-info') {
          parent.data.spaces[attrs.type] = memDetails;
        } else if (parent.tagName === 'mem') {
          parent.data.subSpaces[attrs.type] = memDetails;
        }
      }
      
      if (!isSelfClosing) {
        stack.push({ tagName: 'mem', data: memDetails });
      }
    } else if (tagName === 'gc-end') {
      if (activeGc) {
        activeGc.durationms = parseFloat(attrs.durationms || 0);
        activeGc.cpuUser = parseFloat(attrs.usertimems || 0);
        activeGc.cpuSystem = parseFloat(attrs.systemtimems || 0);
        activeGc.stalls = parseFloat(attrs.stalltimems || 0);
        activeGc.activeThreads = parseInt(attrs.activeThreads || 0);
      }
      stack.push({ tagName: 'gc-end', data: activeGc });
    } else if (tagName === 'gc-op') {
      activeOp = {
        id: attrs.id,
        type: attrs.type,
        timems: parseFloat(attrs.timems || 0),
        timestamp: attrs.timestamp
      };
      if (activeGc) {
        activeGc.ops.push(activeOp);
      }
      if (!isSelfClosing) {
        stack.push({ tagName: 'gc-op', data: activeOp });
      }
    } else if (tagName === 'compact-info') {
      if (activeOp && activeGc) {
        activeOp.compact = {
          movecount: parseInt(attrs.movecount || 0),
          movebytes: parseInt(attrs.movebytes || 0),
          reason: attrs.reason
        };
      }
    } else if (tagName === 'heap-resize') {
      const resize = {
        id: attrs.id,
        type: attrs.type, // expand / contract
        space: attrs.space, // nursery / tenure
        amount: parseInt(attrs.amount || 0),
        count: parseInt(attrs.count || 0),
        timems: parseFloat(attrs.timems || 0),
        reason: attrs.reason,
        timestamp: attrs.timestamp
      };
      state.heapResizes.push(resize);
      if (activeGc) {
        activeGc.resizes.push(resize);
      }
    }
  }
}

/* ----------------------------------------------------
   4. METRICS COMPUTATION
---------------------------------------------------- */
function computeStats() {
  const gcs = state.gcEvents;
  if (gcs.length === 0) return;
  
  // Filter out any events that didn't complete (missing memBefore or memAfter)
  state.gcEvents = gcs.filter(e => e.memBefore && e.memAfter);
  const events = state.gcEvents;
  
  // Computations
  let totalPause = 0;
  let maxPause = 0;
  let maxPauseType = '';
  let scavenges = 0;
  let globals = 0;
  let scavengePause = 0;
  let globalPause = 0;
  let reclaimedBytes = 0;
  
  events.forEach(e => {
    totalPause += e.durationms;
    
    // Reclaimed bytes math
    const usedBefore = e.memBefore.total - e.memBefore.free;
    const usedAfter = e.memAfter.total - e.memAfter.free;
    e.reclaimedBytes = Math.max(0, usedBefore - usedAfter);
    reclaimedBytes += e.reclaimedBytes;
    
    if (e.durationms > maxPause) {
      maxPause = e.durationms;
      maxPauseType = e.type === 'scavenge' ? 'Scavenge GC' : 'Global GC';
    }
    
    if (e.type === 'scavenge') {
      scavenges++;
      scavengePause += e.durationms;
    } else if (e.type === 'global') {
      globals++;
      globalPause += e.durationms;
    }
  });
  
  // Time span
  const firstTime = events[0].timeEpoch;
  const lastTime = events[events.length - 1].timeEpoch;
  const runTimeSec = (lastTime - firstTime) / 1000;
  
  // Allocation rates calculation
  // We can estimate the allocation rate by seeing how much free space in nursery decreased between GC runs.
  let totalAllocatedBytes = 0;
  for (let i = 1; i < events.length; i++) {
    const prev = events[i - 1];
    const curr = events[i];
    
    // Heap used after prev GC
    const prevUsed = prev.memAfter.total - prev.memAfter.free;
    // Heap used before curr GC
    const currUsed = curr.memBefore.total - curr.memBefore.free;
    
    if (currUsed > prevUsed) {
      totalAllocatedBytes += (currUsed - prevUsed);
    }
  }

  // Intervals
  let totalInterval = 0;
  for (let i = 1; i < events.length; i++) {
    totalInterval += (events[i].timeEpoch - events[i - 1].timeEpoch) / 1000;
  }
  
  // Set calculated stats
  state.metrics.totalGCTime = totalPause;
  state.metrics.totalCycles = events.length;
  state.metrics.scavengeCount = scavenges;
  state.metrics.globalCount = globals;
  state.metrics.avgScavengePause = scavenges ? (scavengePause / scavenges) : 0;
  state.metrics.avgGlobalPause = globals ? (globalPause / globals) : 0;
  state.metrics.maxPause = maxPause;
  state.metrics.maxPauseType = maxPauseType;
  state.metrics.totalRunTimeSec = runTimeSec || 1;
  state.metrics.gcOverheadPct = (totalPause / (state.metrics.totalRunTimeSec * 1000)) * 100;
  state.metrics.totalReclaimedBytes = reclaimedBytes;
  state.metrics.avgReclaimedBytes = reclaimedBytes / events.length;
  state.metrics.avgIntervalSec = events.length > 1 ? (totalInterval / (events.length - 1)) : 0;
  state.metrics.allocTotalBytes = totalAllocatedBytes;
  state.metrics.allocRateMbSec = runTimeSec ? (totalAllocatedBytes / (1024 * 1024) / runTimeSec) : 0;
}

/* ----------------------------------------------------
   5. UI CONTROLS & UPDATES
---------------------------------------------------- */
function updateUI() {
  // Update Header
  document.getElementById('current-filename').innerText = state.fileName;
  document.getElementById('header-total-cycles').innerText = state.metrics.totalCycles;
  document.getElementById('header-overhead-pct').innerText = `${state.metrics.gcOverheadPct.toFixed(2)}%`;
  
  // Update KPI Cards
  document.getElementById('kpi-overhead').innerText = `${state.metrics.gcOverheadPct.toFixed(2)}%`;
  document.getElementById('kpi-overhead-sub').innerText = `${formatDuration(state.metrics.totalGCTime)} total GC duration`;
  
  document.getElementById('kpi-max-pause').innerText = `${state.metrics.maxPause.toFixed(1)} ms`;
  document.getElementById('kpi-max-pause-type').innerText = state.metrics.maxPauseType;
  
  document.getElementById('kpi-avg-scavenge').innerText = `${state.metrics.avgScavengePause.toFixed(1)} ms`;
  document.getElementById('kpi-scavenge-count').innerText = `${state.metrics.scavengeCount} scavenge cycles`;
  
  document.getElementById('kpi-avg-interval').innerText = `${state.metrics.avgIntervalSec.toFixed(1)}s`;
  document.getElementById('kpi-interval-frequency').innerText = `1 GC every ${state.metrics.avgIntervalSec.toFixed(1)}s`;
  
  // Update JVM Specs
  document.getElementById('spec-policy').innerText = state.jvmInfo.gcPolicy;
  document.getElementById('spec-max-heap').innerText = state.jvmInfo.maxHeapSize;
  document.getElementById('spec-init-heap').innerText = state.jvmInfo.initialHeapSize;
  document.getElementById('spec-gc-threads').innerText = state.jvmInfo.gcthreads;
  document.getElementById('spec-cpus').innerText = state.jvmInfo.cpus;
  document.getElementById('spec-os').innerText = state.jvmInfo.os;
  document.getElementById('spec-compressed-refs').innerText = state.jvmInfo.compressedRefs;
  
  // Render VM Args
  const vmargsBox = document.getElementById('vmargs-container');
  if (state.jvmInfo.vmargs.length > 0) {
    vmargsBox.innerHTML = state.jvmInfo.vmargs.map(arg => `<span class="vmarg-line">${arg}</span>`).join('');
  } else {
    vmargsBox.innerHTML = '<p class="empty-state">No VM startup arguments found in XML header.</p>';
  }
  
  // Render Breakdown Labels
  document.getElementById('legend-scavenge-val').innerText = `${state.metrics.scavengeCount} (${(state.metrics.scavengeCount/state.metrics.totalCycles*100).toFixed(0)}%)`;
  document.getElementById('legend-global-val').innerText = `${state.metrics.globalCount} (${(state.metrics.globalCount/state.metrics.totalCycles*100).toFixed(0)}%)`;
  document.getElementById('legend-resize-val').innerText = `${state.heapResizes.length} resizes`;
  
  // Render Resizing Tab Metrics
  document.getElementById('resize-expansions-count').innerText = state.heapResizes.filter(r => r.type === 'expand').length;
  document.getElementById('resize-contractions-count').innerText = state.heapResizes.filter(r => r.type === 'contract' || r.type.includes('contract')).length;
  
  // Compute max observed heap
  let maxObservedHeap = 0;
  state.gcEvents.forEach(e => {
    if (e.memBefore.total > maxObservedHeap) maxObservedHeap = e.memBefore.total;
  });
  document.getElementById('resize-max-heap-size').innerText = formatBytes(maxObservedHeap);
  
  const expansions = state.heapResizes.filter(r => r.type === 'expand');
  const avgExpSize = expansions.length ? (expansions.reduce((acc, curr) => acc + curr.amount, 0) / expansions.length) : 0;
  document.getElementById('resize-avg-expansion').innerText = formatBytes(avgExpSize);
  
  // Memory Rates
  document.getElementById('alloc-total-bytes').innerText = formatBytes(state.metrics.allocTotalBytes);
  document.getElementById('alloc-rate-sec').innerText = `${state.metrics.allocRateMbSec.toFixed(1)} MB/s`;
  document.getElementById('alloc-reclaimed-total').innerText = formatBytes(state.metrics.totalReclaimedBytes);
  document.getElementById('alloc-reclaimed-avg').innerText = formatBytes(state.metrics.avgReclaimedBytes);
  
  // Trigger table filtering & pagination reset
  filterTableEvents();
}

function setupNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  const tabPanes = document.querySelectorAll('.tab-pane');
  const viewTitle = document.getElementById('view-title');
  
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const tabId = item.getAttribute('data-tab');
      
      navItems.forEach(n => n.classList.remove('active'));
      tabPanes.forEach(t => t.classList.remove('active'));
      
      item.classList.add('active');
      document.getElementById(tabId).classList.add('active');
      
      // Update header title
      viewTitle.innerText = item.querySelector('span').innerText;
    });
  });
  
  // Memory Space View Toggles
  const memoryToggles = document.querySelectorAll('[data-memory-view]');
  memoryToggles.forEach(toggle => {
    toggle.addEventListener('click', () => {
      memoryToggles.forEach(btn => btn.classList.remove('active'));
      toggle.classList.add('active');
      const viewMode = toggle.getAttribute('data-memory-view');
      renderMemoryChart(viewMode);
    });
  });
}

/* ----------------------------------------------------
   6. CHART VISUALIZATION
---------------------------------------------------- */
function initCharts() {
  // GC Breakdown Doughnut Chart
  const ctxBreakdown = document.getElementById('gcBreakdownChart').getContext('2d');
  if (gcBreakdownChartInstance) gcBreakdownChartInstance.destroy();
  
  gcBreakdownChartInstance = new Chart(ctxBreakdown, {
    type: 'doughnut',
    data: {
      labels: ['Scavenge', 'Global'],
      datasets: [{
        data: [state.metrics.scavengeCount, state.metrics.globalCount],
        backgroundColor: ['#3b82f6', '#ef4444'],
        borderWidth: 0,
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      cutout: '75%'
    }
  });

  // Memory usage timeline line chart (default to Total Heap view)
  renderMemoryChart('heap');
  
  // GC Duration scatter chart
  renderDurationChart();
  
  // Reclaimed memory bar chart
  renderReclaimedChart();
  
  // Force theme colors update
  updateChartsTheme();
}

function renderMemoryChart(mode) {
  const ctxMem = document.getElementById('memoryChart').getContext('2d');
  if (memoryChartInstance) memoryChartInstance.destroy();
  
  const events = state.gcEvents;
  
  // Prepare raw datasets depending on the mode
  let datasets = [];
  
  if (mode === 'heap') {
    // Total heap metrics
    const totalHeapData = events.map(e => ({ x: e.timeEpoch, y: e.memBefore.total / (1024*1024) }));
    const usedBeforeData = events.map(e => ({ x: e.timeEpoch, y: (e.memBefore.total - e.memBefore.free) / (1024*1024) }));
    const usedAfterData = events.map(e => ({ x: e.timeEpoch, y: (e.memAfter.total - e.memAfter.free) / (1024*1024) }));
    
    // Downsample values for performance while preserving GC spikes/troughs
    datasets = [
      {
        label: 'Total Heap Limit',
        data: downsampleMinMax(totalHeapData, 500),
        borderColor: '#10b981',
        borderWidth: 2,
        pointRadius: 0,
        fill: false,
        stepped: true
      },
      {
        label: 'Used (Before GC)',
        data: downsampleMinMax(usedBeforeData, 500),
        borderColor: '#ef4444',
        borderWidth: 1.5,
        borderDash: [3, 3],
        pointRadius: 1,
        fill: false
      },
      {
        label: 'Used (After GC)',
        data: downsampleMinMax(usedAfterData, 500),
        borderColor: '#f59e0b',
        borderWidth: 2,
        pointRadius: 1,
        fill: false
      }
    ];
  } else if (mode === 'nursery') {
    // Nursery space details
    const getVal = (e, path, detail) => {
      const space = e[path].spaces.nursery;
      if (!space) return 0;
      if (detail === 'total') return space.total / (1024*1024);
      return (space.total - space.free) / (1024*1024);
    };
    
    const nurseryTotal = events.map(e => ({ x: e.timeEpoch, y: getVal(e, 'memBefore', 'total') }));
    const nurseryUsedBefore = events.map(e => ({ x: e.timeEpoch, y: getVal(e, 'memBefore', 'used') }));
    const nurseryUsedAfter = events.map(e => ({ x: e.timeEpoch, y: getVal(e, 'memAfter', 'used') }));
    
    datasets = [
      {
        label: 'Nursery Size',
        data: downsampleMinMax(nurseryTotal, 500),
        borderColor: '#3b82f6',
        borderWidth: 2,
        pointRadius: 0,
        fill: false,
        stepped: true
      },
      {
        label: 'Used (Before GC)',
        data: downsampleMinMax(nurseryUsedBefore, 500),
        borderColor: 'rgba(59, 130, 246, 0.4)',
        borderWidth: 1.5,
        pointRadius: 1,
        fill: false
      },
      {
        label: 'Used (After GC)',
        data: downsampleMinMax(nurseryUsedAfter, 500),
        borderColor: '#8b5cf6',
        borderWidth: 2,
        pointRadius: 1,
        fill: false
      }
    ];
  } else if (mode === 'tenure') {
    // Tenure space details
    const getVal = (e, path, detail) => {
      const space = e[path].spaces.tenure;
      if (!space) return 0;
      if (detail === 'total') return space.total / (1024*1024);
      return (space.total - space.free) / (1024*1024);
    };
    
    const tenureTotal = events.map(e => ({ x: e.timeEpoch, y: getVal(e, 'memBefore', 'total') }));
    const tenureUsedBefore = events.map(e => ({ x: e.timeEpoch, y: getVal(e, 'memBefore', 'used') }));
    const tenureUsedAfter = events.map(e => ({ x: e.timeEpoch, y: getVal(e, 'memAfter', 'used') }));
    
    datasets = [
      {
        label: 'Tenure Size',
        data: downsampleMinMax(tenureTotal, 500),
        borderColor: '#10b981',
        borderWidth: 2,
        pointRadius: 0,
        fill: false,
        stepped: true
      },
      {
        label: 'Used (Before GC)',
        data: downsampleMinMax(tenureUsedBefore, 500),
        borderColor: 'rgba(16, 185, 129, 0.4)',
        borderWidth: 1.5,
        pointRadius: 1,
        fill: false
      },
      {
        label: 'Used (After GC)',
        data: downsampleMinMax(tenureUsedAfter, 500),
        borderColor: '#f59e0b',
        borderWidth: 2,
        pointRadius: 1,
        fill: false
      }
    ];
  }
  
  memoryChartInstance = new Chart(ctxMem, {
    type: 'line',
    data: { datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: 'index',
        intersect: false
      },
      plugins: {
        legend: { display: true, position: 'top' },
        tooltip: {
          callbacks: {
            label: (ctx) => `${ctx.dataset.label}: ${ctx.parsed.y.toFixed(1)} MB`
          }
        }
      },
      scales: {
        x: {
          type: 'linear',
          ticks: {
            callback: (val) => formatTimeLabel(val)
          }
        },
        y: {
          title: { display: true, text: 'Memory (MB)' }
        }
      }
    }
  });
}

function renderDurationChart() {
  const ctxDuration = document.getElementById('gcDurationChart').getContext('2d');
  if (gcDurationChartInstance) gcDurationChartInstance.destroy();
  
  const events = state.gcEvents;
  
  // Format pause time points
  const scavengePoints = events.filter(e => e.type === 'scavenge').map(e => ({ x: e.timeEpoch, y: e.durationms }));
  const globalPoints = events.filter(e => e.type === 'global').map(e => ({ x: e.timeEpoch, y: e.durationms }));
  
  gcDurationChartInstance = new Chart(ctxDuration, {
    type: 'scatter',
    data: {
      datasets: [
        {
          label: 'Scavenge GC',
          data: downsampleMinMax(scavengePoints, 400),
          backgroundColor: 'rgba(59, 130, 246, 0.7)',
          pointRadius: 4,
          pointHoverRadius: 6
        },
        {
          label: 'Global GC',
          data: downsampleMinMax(globalPoints, 200),
          backgroundColor: 'rgba(239, 68, 68, 0.9)',
          pointRadius: 6,
          pointHoverRadius: 8
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => `${ctx.dataset.label} Pause: ${ctx.parsed.y.toFixed(1)} ms`
          }
        }
      },
      scales: {
        x: {
          type: 'linear',
          ticks: {
            callback: (val) => formatTimeLabel(val)
          }
        },
        y: {
          title: { display: true, text: 'Pause Time (ms)' },
          min: 0
        }
      }
    }
  });
}

function renderReclaimedChart() {
  const ctxRec = document.getElementById('reclaimedChart').getContext('2d');
  if (reclaimedChartInstance) reclaimedChartInstance.destroy();
  
  const events = state.gcEvents;
  const dataPoints = events.map(e => ({ x: e.timeEpoch, y: e.reclaimedBytes / (1024 * 1024) }));
  
  reclaimedChartInstance = new Chart(ctxRec, {
    type: 'bar',
    data: {
      datasets: [{
        label: 'Reclaimed Garbage',
        data: downsampleMinMax(dataPoints, 600),
        backgroundColor: 'rgba(16, 185, 129, 0.55)',
        borderColor: '#10b981',
        borderWidth: 1,
        barThickness: 'flex'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => `Reclaimed: ${ctx.parsed.y.toFixed(1)} MB`
          }
        }
      },
      scales: {
        x: {
          type: 'linear',
          ticks: {
            callback: (val) => formatTimeLabel(val)
          }
        },
        y: {
          title: { display: true, text: 'Memory Reclaimed (MB)' },
          min: 0
        }
      }
    }
  });
}

// Memory Min-Max Downsampling (keeps peaks and troughs intact)
function downsampleMinMax(data, targetSize) {
  if (data.length <= targetSize) return data;
  
  const bucketSize = Math.floor(data.length / (targetSize / 2));
  const result = [];
  
  for (let i = 0; i < data.length; i += bucketSize) {
    const bucket = data.slice(i, i + bucketSize);
    if (bucket.length === 0) continue;
    
    let minPt = bucket[0];
    let maxPt = bucket[0];
    
    for (let j = 1; j < bucket.length; j++) {
      if (bucket[j].y < minPt.y) minPt = bucket[j];
      if (bucket[j].y > maxPt.y) maxPt = bucket[j];
    }
    
    if (minPt.x < maxPt.x) {
      result.push(minPt);
      result.push(maxPt);
    } else if (minPt.x > maxPt.x) {
      result.push(maxPt);
      result.push(minPt);
    } else {
      result.push(minPt);
    }
  }
  return result;
}

/* ----------------------------------------------------
   7. TABLE EXPLORER (SEARCH, SORT, FILTER, PAGINATE)
---------------------------------------------------- */
function setupTableFilters() {
  const searchInput = document.getElementById('log-search');
  const typeFilter = document.getElementById('filter-type');
  const durationFilter = document.getElementById('filter-duration');
  const resizeFilter = document.getElementById('filter-resize');
  
  const triggers = [searchInput, typeFilter, durationFilter, resizeFilter];
  triggers.forEach(el => {
    el.addEventListener('input', () => {
      state.pagination.currentPage = 1;
      filterTableEvents();
    });
  });
  
  // Setup sorting header listeners
  const headers = document.querySelectorAll('.data-table th.sortable');
  headers.forEach(h => {
    h.addEventListener('click', () => {
      const sortField = h.getAttribute('data-sort');
      if (state.sorting.field === sortField) {
        state.sorting.ascending = !state.sorting.ascending;
      } else {
        state.sorting.field = sortField;
        state.sorting.ascending = true;
      }
      
      // Update icons
      headers.forEach(el => {
        const icon = el.querySelector('.sort-icon');
        icon.style.opacity = '0.3';
        icon.style.transform = 'rotate(0deg)';
      });
      const currIcon = h.querySelector('.sort-icon');
      currIcon.style.opacity = '0.9';
      currIcon.style.transform = state.sorting.ascending ? 'rotate(180deg)' : 'rotate(0deg)';
      
      sortFilteredEvents();
      renderTable();
    });
  });
}

function filterTableEvents() {
  const query = document.getElementById('log-search').value.toLowerCase();
  const type = document.getElementById('filter-type').value;
  const durationThreshold = document.getElementById('filter-duration').value;
  const resizeOnly = document.getElementById('filter-resize').value === 'resized';
  
  state.pagination.filteredEvents = state.gcEvents.filter(e => {
    // 1. Text Search
    if (query && !e.timestamp.toLowerCase().includes(query) && !e.id.toString().includes(query)) {
      return false;
    }
    // 2. GC Type Filter
    if (type !== 'all' && e.type !== type) {
      return false;
    }
    // 3. Pause Duration Filter
    if (durationThreshold !== 'all') {
      const minDuration = parseFloat(durationThreshold);
      if (e.durationms < minDuration) return false;
    }
    // 4. Resize Event Filter
    if (resizeOnly && e.resizes.length === 0) {
      return false;
    }
    return true;
  });
  
  sortFilteredEvents();
  renderTable();
}

function sortFilteredEvents() {
  const field = state.sorting.field;
  const asc = state.sorting.ascending;
  
  state.pagination.filteredEvents.sort((a, b) => {
    let valA, valB;
    
    if (field === 'id') {
      valA = parseInt(a.id);
      valB = parseInt(b.id);
    } else if (field === 'timestamp') {
      valA = a.timeEpoch;
      valB = b.timeEpoch;
    } else if (field === 'type') {
      valA = a.type;
      valB = b.type;
    } else if (field === 'duration') {
      valA = a.durationms;
      valB = b.durationms;
    } else if (field === 'before') {
      valA = a.memBefore.total - a.memBefore.free;
      valB = b.memBefore.total - b.memBefore.free;
    } else if (field === 'after') {
      valA = a.memAfter.total - a.memAfter.free;
      valB = b.memAfter.total - b.memAfter.free;
    } else if (field === 'reclaimed') {
      valA = a.reclaimedBytes;
      valB = b.reclaimedBytes;
    }
    
    if (valA < valB) return asc ? -1 : 1;
    if (valA > valB) return asc ? 1 : -1;
    return 0;
  });
}

function renderTable() {
  const tableBody = document.getElementById('log-table-body');
  const pag = state.pagination;
  const total = pag.filteredEvents.length;
  
  if (total === 0) {
    tableBody.innerHTML = '<tr><td colspan="8" class="empty-state">No matching GC events found.</td></tr>';
    document.getElementById('pag-start').innerText = '0';
    document.getElementById('pag-end').innerText = '0';
    document.getElementById('pag-total').innerText = '0';
    return;
  }
  
  const startIdx = (pag.currentPage - 1) * pag.pageSize;
  const endIdx = Math.min(startIdx + pag.pageSize, total);
  
  const pageSlice = pag.filteredEvents.slice(startIdx, endIdx);
  
  tableBody.innerHTML = pageSlice.map(e => {
    const usedBefore = e.memBefore.total - e.memBefore.free;
    const usedAfter = e.memAfter.total - e.memAfter.free;
    
    // Add badge elements for resize
    const typeLabel = e.type === 'scavenge' ? 'Scavenge' : 'Global';
    const resizeBadge = e.resizes.length > 0 ? `<span class="badge-cell resize">Resize</span>` : '';
    
    return `
      <tr>
        <td class="font-mono">#${e.id}</td>
        <td>${formatTimestamp(e.timestamp)}</td>
        <td>
          <span class="badge-cell ${e.type}">${typeLabel}</span>
          ${resizeBadge}
        </td>
        <td class="text-right font-mono font-bold">${e.durationms.toFixed(2)}</td>
        <td class="text-right font-mono">${formatBytes(usedBefore)}</td>
        <td class="text-right font-mono">${formatBytes(usedAfter)}</td>
        <td class="text-right font-mono text-green font-bold">+${formatBytes(e.reclaimedBytes)}</td>
        <td>
          <button class="inspect-btn" onclick="inspectGcEvent('${e.id}')">
            <i data-lucide="eye"></i> Inspect
          </button>
        </td>
      </tr>
    `;
  }).join('');
  
  // Re-run lucide to render buttons icons
  lucide.createIcons();
  
  // Update pagination info
  document.getElementById('pag-start').innerText = startIdx + 1;
  document.getElementById('pag-end').innerText = endIdx;
  document.getElementById('pag-total').innerText = total;
  
  renderPaginationNumbers();
}

function setupPagination() {
  document.getElementById('pag-prev-btn').addEventListener('click', () => {
    if (state.pagination.currentPage > 1) {
      state.pagination.currentPage--;
      renderTable();
    }
  });
  
  document.getElementById('pag-next-btn').addEventListener('click', () => {
    const totalPages = Math.ceil(state.pagination.filteredEvents.length / state.pagination.pageSize);
    if (state.pagination.currentPage < totalPages) {
      state.pagination.currentPage++;
      renderTable();
    }
  });
}

function renderPaginationNumbers() {
  const pagNumbers = document.getElementById('pag-numbers');
  const totalPages = Math.ceil(state.pagination.filteredEvents.length / state.pagination.pageSize);
  const current = state.pagination.currentPage;
  
  document.getElementById('pag-prev-btn').disabled = (current === 1);
  document.getElementById('pag-next-btn').disabled = (current === totalPages || totalPages === 0);
  
  let html = '';
  // Show first page, active page context, and last page
  const pageRange = 1; // context range
  
  for (let i = 1; i <= totalPages; i++) {
    if (i === 1 || i === totalPages || (i >= current - pageRange && i <= current + pageRange)) {
      html += `<button class="pag-num ${i === current ? 'active' : ''}" onclick="goToPage(${i})">${i}</button>`;
    } else if (i === current - pageRange - 1 || i === current + pageRange + 1) {
      html += `<span class="pag-ellipsis text-muted">...</span>`;
    }
  }
  
  pagNumbers.innerHTML = html;
}

window.goToPage = (page) => {
  state.pagination.currentPage = page;
  renderTable();
};

/* ----------------------------------------------------
   8. SLIDE-OUT GC INSPECTOR
---------------------------------------------------- */
window.inspectGcEvent = (id) => {
  const e = state.gcEvents.find(event => event.id === id);
  if (!e) return;
  
  // Open overlay
  const drawer = document.getElementById('detail-drawer');
  drawer.classList.remove('hidden');
  
  // Set values
  document.getElementById('drawer-event-id').innerText = `Event ID: #${e.id}`;
  document.getElementById('drawer-time').innerText = formatTimestamp(e.timestamp);
  document.getElementById('drawer-duration').innerText = `${e.durationms.toFixed(2)} ms`;
  document.getElementById('drawer-type').innerText = e.type === 'scavenge' ? 'Scavenge (Nursery)' : 'Global (Heap)';
  document.getElementById('drawer-reclaimed').innerText = formatBytes(e.reclaimedBytes);
  
  // Performance numbers
  document.getElementById('drawer-cpu-system').innerText = `${e.cpuSystem.toFixed(2)} ms`;
  document.getElementById('drawer-cpu-user').innerText = `${e.cpuUser.toFixed(2)} ms`;
  document.getElementById('drawer-stalls').innerText = `${e.stalls.toFixed(2)} ms`;
  document.getElementById('drawer-active-threads').innerText = e.activeThreads;
  
  // Allocation/Resize
  document.getElementById('drawer-req-bytes').innerText = e.allocationRequest ? formatBytes(e.allocationRequest) : '-';
  document.getElementById('drawer-trigger').innerText = e.triggerReason;
  
  const resStr = e.resizes.length ? e.resizes.map(r => `${r.type} ${r.space} by ${formatBytes(r.amount)}`).join(', ') : 'None';
  document.getElementById('drawer-resize-event').innerText = resStr;
  
  // Spaces Details
  // 1. Nursery before/after
  const nsB = e.memBefore.spaces.nursery;
  const nsA = e.memAfter.spaces.nursery;
  if (nsB && nsA) {
    document.getElementById('drawer-nursery-tot-before').innerText = formatBytes(nsB.total);
    document.getElementById('drawer-nursery-tot-after').innerText = formatBytes(nsA.total);
    document.getElementById('drawer-nursery-free-before').innerText = formatBytes(nsB.free);
    document.getElementById('drawer-nursery-free-after').innerText = formatBytes(nsA.free);
    
    const allocB = nsB.subSpaces.allocate;
    const allocA = nsA.subSpaces.allocate;
    document.getElementById('drawer-alloc-free-before').innerText = allocB ? formatBytes(allocB.free) : '-';
    document.getElementById('drawer-alloc-free-after').innerText = allocA ? formatBytes(allocA.free) : '-';
    
    const survB = nsB.subSpaces.survivor;
    const survA = nsA.subSpaces.survivor;
    document.getElementById('drawer-surv-free-before').innerText = survB ? formatBytes(survB.free) : '-';
    document.getElementById('drawer-surv-free-after').innerText = survA ? formatBytes(survA.free) : '-';
  }
  
  // 2. Tenure before/after
  const tenB = e.memBefore.spaces.tenure;
  const tenA = e.memAfter.spaces.tenure;
  if (tenB && tenA) {
    document.getElementById('drawer-tenure-tot-before').innerText = formatBytes(tenB.total);
    document.getElementById('drawer-tenure-tot-after').innerText = formatBytes(tenA.total);
    document.getElementById('drawer-tenure-free-before').innerText = formatBytes(tenB.free);
    document.getElementById('drawer-tenure-free-after').innerText = formatBytes(tenA.free);
    
    const soaB = tenB.subSpaces.soa;
    const soaA = tenA.subSpaces.soa;
    document.getElementById('drawer-soa-free-before').innerText = soaB ? formatBytes(soaB.free) : '-';
    document.getElementById('drawer-soa-free-after').innerText = soaA ? formatBytes(soaA.free) : '-';
    
    const loaB = tenB.subSpaces.loa;
    const loaA = tenA.subSpaces.loa;
    document.getElementById('drawer-loa-free-before').innerText = loaB ? formatBytes(loaB.free) : '-';
    document.getElementById('drawer-loa-free-after').innerText = loaA ? formatBytes(loaA.free) : '-';
  }
  
  // Raw XML string escape & formatting
  const xmlDisplay = document.getElementById('drawer-raw-xml');
  xmlDisplay.textContent = e.rawXml.trim();
  
  // Close buttons setup
  const closeBtn = document.getElementById('close-drawer-btn');
  closeBtn.onclick = () => drawer.classList.add('hidden');
  
  drawer.onclick = (event) => {
    if (event.target === drawer) drawer.classList.add('hidden');
  };
};

function setupDrawerTabs() {
  const tabs = document.querySelectorAll('.drawer-tab-btn');
  const panels = document.querySelectorAll('.drawer-tab-panel');
  
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const panelId = `drawer-tab-${tab.getAttribute('data-drawer-tab')}`;
      
      tabs.forEach(t => t.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));
      
      tab.classList.add('active');
      document.getElementById(panelId).classList.add('active');
    });
  });
}

/* ----------------------------------------------------
   9. HEALTH DIAGNOSTIC ENGINE (AI INSIGHTS)
---------------------------------------------------- */
function runDiagnostics() {
  const alertsContainer = document.getElementById('diagnostics-alerts');
  const listContainer = document.getElementById('recommendation-list');
  const badge = document.getElementById('diagnostic-badge');
  const healthStatus = document.getElementById('health-status-text');
  
  const alerts = [];
  const recommendations = [];
  
  // Rule 1: GC Overhead
  const overhead = state.metrics.gcOverheadPct;
  if (overhead > 10) {
    alerts.push({
      severity: 'danger',
      title: 'Critical GC Overhead Detected',
      desc: `The JVM is spending ${overhead.toFixed(2)}% of its active run time processing GC pauses. This is extremely severe (above 10% threshold) and causes heavy latency or app thread starvation.`
    });
    recommendations.push({
      title: 'Tune Heap Sizes & Nursery Ratio',
      desc: 'Significant overhead indicates the active heap sizes are too small to support the application allocation footprint. Increase memory sizes by expanding <code>-Xmx</code>, or investigate nursery allocation scaling.'
    });
  } else if (overhead > 4.5) {
    alerts.push({
      severity: 'warning',
      title: 'High GC Overhead Warning',
      desc: `The JVM is spending ${overhead.toFixed(2)}% of its run time in GC stalls. Ideal overhead for a healthy production Java app should be less than 2-3%.`
    });
  }
  
  // Rule 2: Max Pause Duration
  const maxPause = state.metrics.maxPause;
  if (maxPause > 2000) {
    alerts.push({
      severity: 'danger',
      title: 'Severe Stop-The-World Pauses',
      desc: `A maximum GC pause of ${maxPause.toFixed(0)} ms was observed. Stop-the-world pauses exceeding 2 seconds cause thread timeouts, network timeout responses, and sluggish performance.`
    });
  } else if (maxPause > 500) {
    alerts.push({
      severity: 'warning',
      title: 'Prolonged Response Delay',
      desc: `The maximum observed stop-the-world stall was ${maxPause.toFixed(0)} ms. While acceptable in batch processes, it is too high for responsive microservices or web endpoints.`
    });
  }
  
  // Rule 3: Frequent Scavenges (Nursery Size check)
  const interval = state.metrics.avgIntervalSec;
  if (interval < 1.5 && state.metrics.scavengeCount > 10) {
    alerts.push({
      severity: 'warning',
      title: 'Frequent Nursery Scavenges',
      desc: `GC cycles are occurring extremely frequently, averaging one collection every ${interval.toFixed(1)} seconds. Frequent scavenges indicates nursery space fills up too quickly.`
    });
    recommendations.push({
      title: 'Expand Nursery Space',
      desc: `Increase the nursery allocation (using Semeru/J9 flags such as <code>-Xmn</code> or tweaking allocation ratios) to allow objects to die inside the nursery instead of causing constant scavenges.`
    });
  }
  
  // Rule 4: Heap Resizing Thrashing
  const resizes = state.heapResizes.length;
  if (resizes > 15) {
    alerts.push({
      severity: 'warning',
      title: 'Frequent Heap Resizing Activity',
      desc: `The JVM had to resize (expand/contract) its spaces ${resizes} times during this log run. Each resizing event introduces dynamic allocation overhead and JVM pause delays.`
    });
    recommendations.push({
      title: 'Lock Heap Allocation Size (-Xms = -Xmx)',
      desc: 'Eliminate resizing lag by locking initial heap allocation to the maximum limit. Match the value of <code>-Xms</code> to <code>-Xmx</code>. This prevents the JVM from constantly adjusting its heap boundaries.'
    });
  }

  // Rule 5: Memory Leak slope detection
  const events = state.gcEvents;
  if (events.length > 15) {
    // Collect post-GC used memory over timeline
    const dataPoints = events.map(e => ({
      x: (e.timeEpoch - events[0].timeEpoch) / 1000, // seconds from start
      y: (e.memAfter.total - e.memAfter.free) / (1024 * 1024) // used memory in MB
    }));
    
    // Calculate simple linear regression slope
    const n = dataPoints.length;
    let sumX = 0, sumY = 0, sumXY = 0, sumXX = 0;
    dataPoints.forEach(p => {
      sumX += p.x;
      sumY += p.y;
      sumXY += p.x * p.y;
      sumXX += p.x * p.x;
    });
    
    const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
    
    // Check MB/hour rate
    const mbPerHour = slope * 3600;
    
    // Correlation check to filter out heavy fluctuations
    const avgX = sumX / n;
    const avgY = sumY / n;
    let num = 0, denX = 0, denY = 0;
    dataPoints.forEach(p => {
      num += (p.x - avgX) * (p.y - avgY);
      denX += Math.pow(p.x - avgX, 2);
      denY += Math.pow(p.y - avgY, 2);
    });
    const r = denX && denY ? (num / Math.sqrt(denX * denY)) : 0;
    
    // If slope is climbing and high correlation, alert!
    if (mbPerHour > 5.0 && r > 0.6) {
      alerts.push({
        severity: 'danger',
        title: 'Potential Memory Leak Suspected',
        desc: `Memory remaining after GC is climbing steadily at a rate of +${mbPerHour.toFixed(1)} MB/hour (R² = ${(r*r).toFixed(2)}). The JVM is unable to reclaim memory baseline levels.`
      });
      recommendations.push({
        title: 'Run JVM Memory Heap Dump Profile',
        desc: 'Accumulating post-GC retention indicates references to unused objects are kept alive. Capture a heap dump (e.g. using Eclipse Memory Analyzer Tool (MAT)) to inspect classes retaining memory.'
      });
    }
  }
  
  // Rule 6: Defragmentation / Compaction
  let compactions = 0;
  events.forEach(e => {
    e.ops.forEach(op => {
      if (op.compact) compactions++;
    });
  });
  
  if (compactions > 0) {
    alerts.push({
      severity: 'warning',
      title: 'JVM Memory Compaction Stalls',
      desc: `Verbosegc recorded ${compactions} compaction events during tenure collections. Compacting memory is extremely slow as it moves objects in memory.`
    });
    recommendations.push({
      title: 'Analyze Tenure Allocations and LOA Size',
      desc: 'Tenure space compaction occurs due to memory fragmentation (e.g. many large allocations failing to find contiguous blocks). Increase the size of the Large Object Area (LOA) or optimize object recycling.'
    });
  }
  
  // If initial heap size is different from max heap size and no locks
  if (state.jvmInfo.initialHeapSize !== '-' && state.jvmInfo.initialHeapSize !== state.jvmInfo.maxHeapSize) {
    recommendations.push({
      title: 'Align Startup Heap Memory',
      desc: `Your JVM initial size (${state.jvmInfo.initialHeapSize}) is configured smaller than max limit (${state.jvmInfo.maxHeapSize}). Explicitly set <code>-Xms</code> equal to <code>-Xmx</code>.`
    });
  }
  
  // Render Alerts
  if (alerts.length > 0) {
    // Show count on badge
    badge.innerText = alerts.length;
    badge.classList.remove('hidden');
    
    // Render health status text
    const hazards = alerts.filter(a => a.severity === 'danger').length;
    if (hazards > 0) {
      healthStatus.innerText = 'Critical Hazards';
      healthStatus.className = 'gauge-value text-red';
    } else {
      healthStatus.innerText = 'Warnings Active';
      healthStatus.className = 'gauge-value text-amber';
    }
    
    // HTML formatting
    alertsContainer.innerHTML = alerts.map(a => `
      <div class="alert-item ${a.severity}">
        <div class="alert-icon">
          <i data-lucide="${a.severity === 'danger' ? 'alert-triangle' : 'alert-circle'}"></i>
        </div>
        <div class="alert-content">
          <h4 class="alert-title">${a.title}</h4>
          <p class="alert-desc">${a.desc}</p>
        </div>
      </div>
    `).join('');
  } else {
    // Good Health!
    badge.classList.add('hidden');
    healthStatus.innerText = 'Optimal Health';
    healthStatus.className = 'gauge-value text-green';
    
    alertsContainer.innerHTML = `
      <div class="alert-item success">
        <div class="alert-icon">
          <i data-lucide="shield-check"></i>
        </div>
        <div class="alert-content">
          <h4 class="alert-title">Your JVM Health is Good</h4>
          <p class="alert-desc">The static diagnostics engine scanned all GC intervals, heap sizes, resizing occurrences, and compaction flags, and found zero anomalies.</p>
        </div>
      </div>
    `;
  }
  
  // Render recommendations list
  if (recommendations.length > 0) {
    listContainer.innerHTML = recommendations.map(r => `
      <li>
        <strong>${r.title}</strong>
        <p>${r.desc}</p>
      </li>
    `).join('');
  } else {
    listContainer.innerHTML = `
      <li>
        <strong>Optimal Configurations Profiled</strong>
        <p>No configuration optimizations are suggested. Keep monitoring memory usage profiles as load characteristics scale.</p>
      </li>
    `;
  }
  
  // Re-run lucide icons for warnings
  lucide.createIcons();
}

/* ----------------------------------------------------
   10. FORMATTERS & CONVERTERS
---------------------------------------------------- */
function formatBytes(bytes) {
  if (isNaN(bytes) || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(ms) {
  if (ms < 1000) return `${ms.toFixed(0)} ms`;
  const sec = ms / 1000;
  if (sec < 60) return `${sec.toFixed(2)}s`;
  const min = Math.floor(sec / 60);
  const remainingSec = sec % 60;
  return `${min}m ${remainingSec.toFixed(0)}s`;
}

function formatTimestamp(ts) {
  if (!ts) return '-';
  // Strip timezone details or shorten ts for nice displaying
  // ts looks like "2026-03-06T14:16:31.802"
  const idx = ts.indexOf('T');
  if (idx === -1) return ts;
  return ts.substring(0, 10) + ' ' + ts.substring(idx + 1);
}

function formatTimeLabel(epoch) {
  const date = new Date(epoch);
  const pad = (n) => n.toString().padStart(2, '0');
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}
