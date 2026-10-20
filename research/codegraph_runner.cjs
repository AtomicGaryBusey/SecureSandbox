#!/usr/bin/env node
'use strict';

const path = require('node:path');

const bundleRoot = '/opt/secure-sandbox/codegraph';
const CodeGraph = require(path.join(bundleRoot, 'lib/dist/index.js')).default;
const { ToolHandler } = require(path.join(bundleRoot, 'lib/dist/mcp/tools.js'));

const CALLABLE_KINDS = new Set(['file', 'module', 'function', 'method', 'route', 'component']);
const FLOW_EDGE_KINDS = new Set(['calls', 'references', 'instantiates', 'navigates']);
const MAX_REACHABILITY_NODES = 5000;

function publicNode(node) {
  return {
    name: String(node.name || ''),
    qualifiedName: String(node.qualifiedName || ''),
    kind: String(node.kind || ''),
    filePath: String(node.filePath || ''),
    startLine: Number(node.startLine || 0),
    endLine: Number(node.endLine || 0),
  };
}

function resolveSelector(graph, selector, role) {
  if (!selector || typeof selector !== 'object') throw new Error(`invalid_${role}_selector`);
  const symbol = String(selector.symbol || '');
  const filePath = String(selector.filePath || '');
  if (!symbol || symbol.length > 128 || !filePath || filePath.length > 512) {
    throw new Error(`invalid_${role}_selector`);
  }
  const matches = graph.getNodesByName(symbol)
    .filter((node) => node.filePath === filePath && CALLABLE_KINDS.has(node.kind));
  if (matches.length === 0) throw new Error(`${role}_not_found`);
  if (matches.length !== 1) throw new Error(`ambiguous_${role}`);
  return matches[0];
}

function allowedFlowEdge(edge) {
  if (!FLOW_EDGE_KINDS.has(edge.kind)) return false;
  // A generic reference is not control flow. CodeGraph marks function-as-value
  // wiring (callbacks/handlers) with fnRef, which is the only reference form
  // admitted to this conservative reachability profile.
  return edge.kind !== 'references' || edge.metadata?.fnRef === true;
}

function traceReachability(graph, entrypoint, target, maxDepth) {
  if (entrypoint.id === target.id) {
    return { reachable: true, path: [{ node: publicNode(entrypoint), via: null }], nodesExamined: 1, truncated: false };
  }
  const visited = new Set([entrypoint.id]);
  const predecessor = new Map();
  let frontier = [entrypoint.id];
  let found = false;
  let truncated = false;

  for (let depth = 0; depth < maxDepth && frontier.length > 0 && !found; depth += 1) {
    const edges = graph.getOutgoingEdgesFrom(frontier, [...FLOW_EDGE_KINDS]).filter(allowedFlowEdge);
    const next = [];
    for (const edge of edges) {
      if (visited.has(edge.target)) continue;
      if (visited.size >= MAX_REACHABILITY_NODES) {
        truncated = true;
        break;
      }
      visited.add(edge.target);
      predecessor.set(edge.target, { from: edge.source, edge });
      if (edge.target === target.id) {
        found = true;
        break;
      }
      next.push(edge.target);
    }
    frontier = next;
  }

  if (!found) return { reachable: false, path: [], nodesExamined: visited.size, truncated };
  const ids = [target.id];
  while (ids[ids.length - 1] !== entrypoint.id) ids.push(predecessor.get(ids[ids.length - 1]).from);
  ids.reverse();
  const nodes = graph.getNodesByIds(ids);
  const path = ids.map((id, index) => {
    const step = { node: publicNode(nodes.get(id)) , via: null };
    if (index > 0) {
      const edge = predecessor.get(id).edge;
      step.via = {
        kind: String(edge.kind),
        line: Number(edge.line || 0),
        confidence: typeof edge.confidence === 'number' ? edge.confidence : null,
        callbackRegistration: edge.kind === 'references' && edge.metadata?.fnRef === true,
      };
    }
    return step;
  });
  return { reachable: true, path, nodesExamined: visited.size, truncated };
}

async function main() {
  const [operation, projectRoot, argument, rawLimit] = process.argv.slice(2);
  if (!projectRoot || !path.isAbsolute(projectRoot)) throw new Error('invalid_project_root');
  if (operation === 'index') {
    const graph = await CodeGraph.init(projectRoot, { index: false });
    try {
      const result = await graph.indexAll();
      process.stdout.write(JSON.stringify({
        status: 'indexed',
        filesProcessed: Number(result.filesIndexed || result.filesProcessed || 0),
        filesDiscovered: Number(result.filesDiscovered || 0),
        filesSkipped: Number(result.filesSkipped || 0),
        filesErrored: Number(result.filesErrored || 0),
        nodesCreated: Number(result.nodesCreated || 0),
        edgesCreated: Number(result.edgesCreated || 0),
        errors: Array.isArray(result.errors) ? result.errors.slice(0, 20).map((item) => ({
          severity: String(item.severity || ''),
          code: String(item.code || ''),
          filePath: String(item.filePath || ''),
          message: String(item.message || '').slice(0, 500),
        })) : [],
      }) + '\n');
    } finally {
      graph.destroy();
    }
    return;
  }
  if (operation === 'query') {
    const query = String(argument || '');
    const maxFiles = Number(rawLimit);
    if (!query || query.length > 256 || !Number.isInteger(maxFiles) || maxFiles < 1 || maxFiles > 10) {
      throw new Error('invalid_query');
    }
    const graph = await CodeGraph.open(projectRoot, { readOnly: true, sync: false, immutable: true });
    try {
      const handler = new ToolHandler(graph);
      const result = await handler.execute('codegraph_explore', { query, maxFiles });
      const text = String(result.content?.[0]?.text || '');
      if (result.isError) throw new Error('codegraph_query_failed');
      if (text.length > 40000) throw new Error('codegraph_output_too_large');
      process.stdout.write(JSON.stringify({ status: 'ok', text }) + '\n');
    } finally {
      graph.destroy();
    }
    return;
  }
  if (operation === 'reachability') {
    const request = JSON.parse(String(argument || ''));
    const maxDepth = Number(rawLimit);
    if (!Number.isInteger(maxDepth) || maxDepth < 1 || maxDepth > 12) throw new Error('invalid_max_depth');
    const graph = await CodeGraph.open(projectRoot, { readOnly: true, sync: false, immutable: true });
    try {
      const entrypoint = resolveSelector(graph, request.entrypoint, 'entrypoint');
      const target = resolveSelector(graph, request.target, 'target');
      const result = traceReachability(graph, entrypoint, target, maxDepth);
      process.stdout.write(JSON.stringify({
        status: 'ok',
        entrypoint: publicNode(entrypoint),
        target: publicNode(target),
        maxDepth,
        edgeProfile: 'calls-callbacks-instantiation-navigation-v1',
        ...result,
      }) + '\n');
    } finally {
      graph.destroy();
    }
    return;
  }
  throw new Error('invalid_operation');
}

main().catch((error) => {
  process.stderr.write(JSON.stringify({ status: 'rejected', error: String(error.message || error) }) + '\n');
  process.exitCode = 1;
});
