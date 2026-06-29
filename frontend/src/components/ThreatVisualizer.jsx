import { useState, useEffect, useRef } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import * as api from '../api.js';

export default function ThreatVisualizer() {
  const [threatLogs, setThreatLogs] = useState([]);
  const canvasRef = useRef(null);
  const trajectoriesRef = useRef([]);

  // WebSocket Connection
  useEffect(() => {
    const cleanup = api.connectWebSocket((msg) => {
      // Filter block/threat events or any connection updates that might be "malicious"
      // or simply treat "alert" or packet dropping/deny, or any packet with custom conditions as threat logs
      let isThreat = false;
      let title = '';
      let source = '';
      let target = 'Internal Network';
      let action = 'blocked';

      if (msg.event_type === 'alert') {
        isThreat = true;
        title = msg.data?.message || msg.data?.type || 'Alert Triggered';
        source = msg.data?.message?.match(/from\s+([\d.]+)/)?.[1] || 'Unknown IP';
        action = 'flagged';
      } else if (msg.event_type === 'connection' && (msg.data?.state === 'closing' || msg.data?.state === 'closed')) {
        // Just simulate some connections as threats if we want more activity, or stick to alert/packets
        // Let's check packets or custom alert checks
      } else if (msg.event_type === 'packet' && (msg.data?.action === 'deny' || msg.data?.action === 'rate-limit')) {
        isThreat = true;
        title = `Packet ${msg.data.action === 'deny' ? 'Blocked' : 'Rate Limited'}`;
        source = msg.data.src_ip || 'Unknown IP';
        target = msg.data.dst_ip || 'Internal Network';
        action = msg.data.action === 'deny' ? 'blocked' : 'limited';
      }

      // If we don't receive direct packet drops, but still want active visualization, 
      // let's turn any alert or some connection states into trajectories.
      // Let's extract threat indicators
      if (isThreat || msg.event_type === 'alert') {
        const src = source || msg.data?.src_ip || '185.220.101.42';
        const dst = target || msg.data?.dst_ip || '192.168.1.105';
        const type = msg.event_type;

        // Populate local state capped at 50 items
        setThreatLogs((prev) => {
          const updated = [{
            timestamp: msg.timestamp || new Date().toISOString(),
            source: src,
            target: dst,
            type: type,
            action: action,
            message: title || msg.message || 'Threat activity detected'
          }, ...prev];
          return updated.slice(0, 50);
        });

        // Add trajectory for canvas drawing
        if (canvasRef.current) {
          const rect = canvasRef.current.getBoundingClientRect();
          const width = rect.width || 800;
          const height = rect.height || 300;
          
          // Generate a trajectory start (outer circle/sides) and end (center/target)
          const startX = Math.random() < 0.5 ? (Math.random() < 0.5 ? 0 : width) : Math.random() * width;
          const startY = startX === 0 || startX === width ? Math.random() * height : (Math.random() < 0.5 ? 0 : height);
          
          // Targets are clustered around the center or specific servers
          const endX = width / 2 + (Math.random() - 0.5) * 100;
          const endY = height / 2 + (Math.random() - 0.5) * 60;

          trajectoriesRef.current.push({
            id: Math.random().toString(),
            startX,
            startY,
            endX,
            endY,
            currentX: startX,
            currentY: startY,
            progress: 0,
            speed: 0.015 + Math.random() * 0.02,
            color: action === 'blocked' ? '#ff3b5c' : action === 'limited' ? '#ffb800' : '#00d4ff',
            size: 2 + Math.random() * 3,
          });
        }
      }
    });

    return () => {
      if (cleanup && typeof cleanup === 'function') cleanup();
    };
  }, []);

  // Canvas Drawing Loop
  useEffect(() => {
    let animationId;
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    
    const handleResize = () => {
      const rect = canvas.parentElement.getBoundingClientRect();
      canvas.width = rect.width;
      canvas.height = 300; // Fixed visualizer height
    };
    handleResize();
    window.addEventListener('resize', handleResize);

    const render = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      const width = canvas.width;
      const height = canvas.height;

      // Draw stylized radar grid/background
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
      ctx.lineWidth = 1;
      
      // Concentric circles in center
      ctx.beginPath();
      ctx.arc(width / 2, height / 2, 40, 0, Math.PI * 2);
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(width / 2, height / 2, 90, 0, Math.PI * 2);
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(width / 2, height / 2, 150, 0, Math.PI * 2);
      ctx.stroke();

      // Crosshairs
      ctx.beginPath();
      ctx.moveTo(width / 2 - 180, height / 2);
      ctx.lineTo(width / 2 + 180, height / 2);
      ctx.stroke();

      ctx.beginPath();
      ctx.moveTo(width / 2, height / 2 - 120);
      ctx.lineTo(width / 2, height / 2 + 120);
      ctx.stroke();

      // Draw center safe shield/target core
      ctx.fillStyle = 'rgba(59, 130, 246, 0.1)';
      ctx.strokeStyle = 'rgba(59, 130, 246, 0.4)';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.arc(width / 2, height / 2, 15, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();

      // Draw active trajectories
      trajectoriesRef.current.forEach((t, index) => {
        t.progress += t.speed;
        
        // Quadratic bezier curve or simple linear interpolation
        // Let's use linear for simple, robust vector math, but we can add a slight curve
        const dx = t.endX - t.startX;
        const dy = t.endY - t.startY;
        
        // Control point for curve
        const controlX = (t.startX + t.endX) / 2 + (dy * 0.2);
        const controlY = (t.startY + t.endY) / 2 - (dx * 0.2);

        // Calculate quadratic bezier points
        const p = t.progress;
        const mt = 1 - p;
        t.currentX = mt * mt * t.startX + 2 * mt * p * controlX + p * p * t.endX;
        t.currentY = mt * mt * t.startY + 2 * mt * p * controlY + p * p * t.endY;

        // Draw trail
        ctx.beginPath();
        ctx.moveTo(t.startX, t.startY);
        ctx.quadraticCurveTo(controlX, controlY, t.currentX, t.currentY);
        ctx.strokeStyle = t.color + '33'; // Fade opacity
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Draw glowing head
        ctx.beginPath();
        ctx.arc(t.currentX, t.currentY, t.size, 0, Math.PI * 2);
        ctx.fillStyle = t.color;
        ctx.shadowColor = t.color;
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0; // reset
      });

      // Remove completed trajectories
      trajectoriesRef.current = trajectoriesRef.current.filter((t) => {
        if (t.progress >= 1) {
          // Trigger a small "impact/block" shockwave at end location
          return false;
        }
        return true;
      });

      animationId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  // Compute top blocked sources for BarChart
  const topBlockedSources = (() => {
    const counts = {};
    threatLogs.forEach((log) => {
      if (log.source && log.source !== 'Unknown IP') {
        counts[log.source] = (counts[log.source] || 0) + 1;
      }
    });
    return Object.entries(counts)
      .map(([ip, count]) => ({ ip, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  })();

  const cardCls = "bg-white/5 border border-white/10 rounded-lg p-5 shadow-[var(--shadow-md)] hover:shadow-[var(--shadow-lg)] transition-all backdrop-blur-lg hover:border-white/20 duration-300";

  return (
    <div className="space-y-6">
      <div className={cardCls + " relative overflow-hidden bg-slate-950/20 border-white/10"}>
        <div className="absolute top-4 left-4 z-10">
          <span className="text-white text-xs font-bold font-mono tracking-wider uppercase bg-red-600/90 px-2 py-1 rounded shadow-md animate-live">
            ● Real-Time Threat Map
          </span>
        </div>
        <canvas 
          ref={canvasRef} 
          className="w-full bg-transparent block rounded-lg"
          style={{ height: '300px' }}
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className={cardCls}>
          <div className="text-[var(--color-text)] text-sm font-semibold mb-4">Top Blocked Sources</div>
          {topBlockedSources.length === 0 ? (
            <div className="text-[var(--color-text-sec)] text-center py-12 text-sm">No threat logs available yet. Waiting for attack events...</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={topBlockedSources}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--color-bg-border)" />
                <XAxis dataKey="ip" tick={{ fontSize: 10, fill: 'var(--color-text-sec)' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: 'var(--color-text-sec)' }} />
                <Tooltip contentStyle={{ background: 'var(--color-bg-panel)', border: '1px solid var(--color-bg-border)', borderRadius: 8, fontSize: 12, color: 'var(--color-text)' }} />
                <Bar dataKey="count" fill="var(--color-danger)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className={cardCls}>
          <div className="text-[var(--color-text)] text-sm font-semibold mb-4">Live Threat Log (Capped 50)</div>
          <div className="max-h-[220px] overflow-y-auto space-y-2 font-mono text-xs">
            {threatLogs.length === 0 ? (
              <div className="text-[var(--color-text-sec)] text-center py-12 text-sm">Waiting for threat logs...</div>
            ) : (
              threatLogs.map((log, i) => (
                <div key={i} className="flex gap-2 p-2 rounded border border-[var(--color-bg-border)] bg-[var(--color-bg-hover)] items-center">
                  <span className="text-[var(--color-danger)] font-bold">[{log.action?.toUpperCase()}]</span>
                  <span className="text-[var(--color-text-sec)]">{new Date(log.timestamp).toLocaleTimeString()}</span>
                  <span className="text-[var(--color-text)] font-semibold truncate flex-1">
                    {log.source} → {log.target}
                  </span>
                  <span className="text-gray-500 italic max-w-[150px] truncate" title={log.message}>
                    {log.message}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
