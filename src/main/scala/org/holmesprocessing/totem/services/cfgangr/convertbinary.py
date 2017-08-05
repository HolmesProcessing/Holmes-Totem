import angr

# imports for graph handling
import networkx as nx
from networkx.readwrite import json_graph


def generateCFG(binary, analysisType = 'Fast'):
    # Create the angr project for the binary
    project = angr.Project(binary, auto_load_libs = False)

    # Create the Control Flow Graph in Fast or Accurate mode.
    if (analysisType == 'Fast'):
        cfg = project.analyses.CFG()
    elif (analysisType == 'Accurate'):#
        cfg = project.analyses.CFGAccurate()
    else:
        return

    # Iterate through all nodes, and for each of them, add information for address, mnemonic and operands.
    for node in cfg.nodes_iter():
        instructions = project.factory.block(addr=node.addr).capstone.insns
        a = []
        for ins in instructions:
            b = {}
            b['addr'] = ins.address
            b['mnemonic'] = ins.mnemonic
            b['operand'] = ins.op_str
            a.append(b)
        node.label = a

    networkxGraph = cfg.graph
    graph = _truncateGraph(networkxGraph)

    # Convert networkx graph to JSON
    graph_json = json_graph.node_link_data(graph)

    return graph_json


def _truncateGraph(cfg):
    # This method will receive a Networkx graph as input. It generates a new networkx graph from it, by keeping only the
    # information necessary. It returns the new graph.
    sequence = 0
    lookup = {}
    graph = nx.DiGraph()
    # Update the nodes
    for n in cfg.nodes():
        if n not in lookup:
            new_node = str(sequence) + ' ' + repr(n.addr) +  ' ' + str(n.name)
            sequence += 1
            lookup[n] = new_node
            graph.add_node(new_node, label = n.label, syscall = n.syscall)

    # Update the edges
    for src, dst, data in cfg.edges(data=True):
        new_src = lookup[src]
        new_dst = lookup[dst]
        data.pop('ins_addr', None)
        data.pop('stmt_idx', None)
        graph.add_edge(new_src, new_dst, data=data)

    return graph
