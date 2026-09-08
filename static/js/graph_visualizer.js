/**
 * High-Performance Interactive HTML5 Canvas Graph Visualizer for SIH26106
 * Force-directed physics layout with node drag, zoom, pan, and inspector integration.
 */

class InteractiveGraphVisualizer {
  constructor(canvasId, onNodeClickCallback) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.onNodeClick = onNodeClickCallback || (() => {});

    this.nodes = [];
    this.edges = [];
    this.nodeMap = new Map();

    // Camera transform
    this.camera = { x: 0, y: 0, zoom: 1.0 };
    this.isDraggingBg = false;
    this.draggedNode = null;
    this.hoveredNode = null;
    this.lastMouse = { x: 0, y: 0 };

    this.animId = null;
    this.simulationRunning = true;

    this._setupCanvas();
    this._attachEvents();
  }

  _setupCanvas() {
    const rect = this.canvas.parentElement.getBoundingClientRect();
    this.width = rect.width || 800;
    this.height = rect.height || 600;
    this.canvas.width = this.width * window.devicePixelRatio;
    this.canvas.height = this.height * window.devicePixelRatio;
    this.ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    this.camera.x = this.width / 2;
    this.camera.y = this.height / 2;
  }

  loadGraphData(graphData) {
    if (!graphData) return;
    this.nodeMap.clear();

    const rawNodes = graphData.nodes || [];
    const rawEdges = graphData.edges || [];

    // Initialize node positions in a radial cluster
    const angleStep = (Math.PI * 2) / Math.max(1, rawNodes.length);
    this.nodes = rawNodes.map((n, i) => {
      const radius = 120 + Math.random() * 140;
      const angle = i * angleStep;
      const nodeObj = {
        id: n.id,
        label: n.label,
        type: n.type,
        color: n.color || '#00f0ff',
        is_threat: n.is_threat || false,
        details: n.details || {},
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius,
        vx: (Math.random() - 0.5) * 2,
        vy: (Math.random() - 0.5) * 2,
        radius: n.type === 'email' ? 22 : (n.type === 'campaign' ? 24 : 16)
      };
      this.nodeMap.set(n.id, nodeObj);
      return nodeObj;
    });

    this.edges = rawEdges.map(e => ({
      from: this.nodeMap.get(e.from),
      to: this.nodeMap.get(e.to),
      label: e.label || '',
      type: e.type || 'default'
    })).filter(e => e.from && e.to);

    this.simulationRunning = true;
    this.fitView();
    this._startLoop();
  }

  _startLoop() {
    if (this.animId) cancelAnimationFrame(this.animId);
    let iterations = 0;

    const tick = () => {
      if (this.simulationRunning && iterations < 350) {
        this._updatePhysics();
        iterations++;
      }
      this._render();
      this.animId = requestAnimationFrame(tick);
    };
    tick();
  }

  _updatePhysics() {
    const kRepel = 1600;
    const kSpring = 0.04;
    const springLength = 110;
    const damping = 0.85;

    // Repulsion between all nodes
    for (let i = 0; i < this.nodes.length; i++) {
      const n1 = this.nodes[i];
      for (let j = i + 1; j < this.nodes.length; j++) {
        const n2 = this.nodes[j];
        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        if (dist < 380) {
          const force = kRepel / (dist * dist);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          if (n1 !== this.draggedNode) { n1.vx -= fx; n1.vy -= fy; }
          if (n2 !== this.draggedNode) { n2.vx += fx; n2.vy += fy; }
        }
      }
    }

    // Spring attraction along edges
    for (const edge of this.edges) {
      const n1 = edge.from;
      const n2 = edge.to;
      const dx = n2.x - n1.x;
      const dy = n2.y - n1.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = (dist - springLength) * kSpring;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      if (n1 !== this.draggedNode) { n1.vx += fx; n1.vy += fy; }
      if (n2 !== this.draggedNode) { n2.vx -= fx; n2.vy -= fy; }
    }

    // Centering force
    for (const n of this.nodes) {
      if (n === this.draggedNode) continue;
      n.vx -= n.x * 0.008;
      n.vy -= n.y * 0.008;
      n.vx *= damping;
      n.vy *= damping;
      n.x += n.vx;
      n.y += n.vy;
    }
  }

  _render() {
    this.ctx.clearRect(0, 0, this.width, this.height);

    // Subtle background grid
    this._drawGrid();

    this.ctx.save();
    this.ctx.translate(this.camera.x, this.camera.y);
    this.ctx.scale(this.camera.zoom, this.camera.zoom);

    // 1. Draw Edges
    for (const edge of this.edges) {
      const isCrossCampaign = (edge.type === 'threat');
      this.ctx.beginPath();
      this.ctx.moveTo(edge.from.x, edge.from.y);
      this.ctx.lineTo(edge.to.x, edge.to.y);
      this.ctx.strokeStyle = isCrossCampaign ? 'rgba(255, 51, 102, 0.7)' : 'rgba(100, 116, 139, 0.4)';
      this.ctx.lineWidth = isCrossCampaign ? 2.5 : 1.5;
      if (isCrossCampaign) {
        this.ctx.setLineDash([5, 5]);
      } else {
        this.ctx.setLineDash([]);
      }
      this.ctx.stroke();

      // Edge label
      if (edge.label && this.camera.zoom > 0.6) {
        const mx = (edge.from.x + edge.to.x) / 2;
        const my = (edge.from.y + edge.to.y) / 2;
        this.ctx.font = '9px "JetBrains Mono", monospace';
        this.ctx.fillStyle = isCrossCampaign ? '#ff3366' : '#64748b';
        this.ctx.textAlign = 'center';
        this.ctx.fillText(edge.label, mx, my - 4);
      }
    }
    this.ctx.setLineDash([]);

    // 2. Draw Nodes
    for (const n of this.nodes) {
      const isHovered = (n === this.hoveredNode);
      const isDragged = (n === this.draggedNode);

      // Outer glow if threat or hovered
      if (n.is_threat || isHovered) {
        this.ctx.beginPath();
        this.ctx.arc(n.x, n.y, n.radius + 8, 0, Math.PI * 2);
        this.ctx.fillStyle = n.is_threat ? 'rgba(255, 51, 102, 0.25)' : 'rgba(0, 240, 255, 0.25)';
        this.ctx.fill();
      }

      // Node base circle
      this.ctx.beginPath();
      this.ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
      this.ctx.fillStyle = n.color;
      this.ctx.fill();
      this.ctx.strokeStyle = isHovered ? '#ffffff' : (n.is_threat ? '#ff3366' : 'rgba(255, 255, 255, 0.2)');
      this.ctx.lineWidth = isHovered ? 3 : 1.5;
      this.ctx.stroke();

      // Node label
      this.ctx.font = '11px "Inter", sans-serif';
      this.ctx.fillStyle = '#f1f5f9';
      this.ctx.textAlign = 'center';
      this.ctx.fillText(n.label, n.x, n.y + n.radius + 14);

      // Node type indicator tag
      this.ctx.font = '8px "JetBrains Mono", monospace';
      this.ctx.fillStyle = '#94a3b8';
      this.ctx.fillText(n.type.toUpperCase(), n.x, n.y + n.radius + 24);
    }

    this.ctx.restore();
  }

  _drawGrid() {
    this.ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
    this.ctx.lineWidth = 1;
    const step = 40 * this.camera.zoom;
    const offsetX = (this.camera.x % step);
    const offsetY = (this.camera.y % step);

    this.ctx.beginPath();
    for (let x = offsetX; x < this.width; x += step) {
      this.ctx.moveTo(x, 0);
      this.ctx.lineTo(x, this.height);
    }
    for (let y = offsetY; y < this.height; y += step) {
      this.ctx.moveTo(0, y);
      this.ctx.lineTo(this.width, y);
    }
    this.ctx.stroke();
  }

  _attachEvents() {
    this.canvas.addEventListener('mousedown', (e) => {
      const pos = this._screenToWorld(e.offsetX, e.offsetY);
      const clicked = this._getNodeAt(pos.x, pos.y);
      if (clicked) {
        this.draggedNode = clicked;
        this.onNodeClick(clicked);
      } else {
        this.isDraggingBg = true;
      }
      this.lastMouse = { x: e.clientX, y: e.clientY };
    });

    window.addEventListener('mousemove', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      if (this.draggedNode) {
        const pos = this._screenToWorld(mouseX, mouseY);
        this.draggedNode.x = pos.x;
        this.draggedNode.y = pos.y;
        this.simulationRunning = true;
      } else if (this.isDraggingBg) {
        const dx = e.clientX - this.lastMouse.x;
        const dy = e.clientY - this.lastMouse.y;
        this.camera.x += dx;
        this.camera.y += dy;
        this.lastMouse = { x: e.clientX, y: e.clientY };
      } else {
        const pos = this._screenToWorld(mouseX, mouseY);
        this.hoveredNode = this._getNodeAt(pos.x, pos.y);
        this.canvas.style.cursor = this.hoveredNode ? 'pointer' : 'default';
      }
    });

    window.addEventListener('mouseup', () => {
      this.draggedNode = null;
      this.isDraggingBg = false;
    });

    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.12 : 0.89;
      this.zoom(zoomFactor, e.offsetX, e.offsetY);
    });

    window.addEventListener('resize', () => {
      this._setupCanvas();
    });
  }

  zoom(factor, centerX = this.width / 2, centerY = this.height / 2) {
    const newZoom = Math.min(2.5, Math.max(0.3, this.camera.zoom * factor));
    this.camera.x = centerX - (centerX - this.camera.x) * (newZoom / this.camera.zoom);
    this.camera.y = centerY - (centerY - this.camera.y) * (newZoom / this.camera.zoom);
    this.camera.zoom = newZoom;
  }

  fitView() {
    this.camera.x = this.width / 2;
    this.camera.y = this.height / 2;
    this.camera.zoom = 0.9;
  }

  _screenToWorld(sx, sy) {
    return {
      x: (sx - this.camera.x) / this.camera.zoom,
      y: (sy - this.camera.y) / this.camera.zoom
    };
  }

  _getNodeAt(wx, wy) {
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const n = this.nodes[i];
      const dx = n.x - wx;
      const dy = n.y - wy;
      if (dx * dx + dy * dy <= (n.radius + 6) * (n.radius + 6)) {
        return n;
      }
    }
    return null;
  }
}
