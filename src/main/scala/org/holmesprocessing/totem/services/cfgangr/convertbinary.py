import angr
import simuvex
import cle
import os
import json
# imports for graph handling
import networkx as nx
from networkx.readwrite import json_graph


def generateCFG(binary, max_size, analysisType = 'Fast'):
    response = {}
    try:
        # Create the angr project for the binary
        project = angr.Project(binary, auto_load_libs=False)
        binary_size = os.stat(binary).st_size
        max_binary_size = int(max_size) * 1024  # Here we will set a limit of binary files in bytes
        if binary_size > max_binary_size:
            response['error'] = 'CFG generation failed because the binary size is too big'
            return json.dumps(response)
        # Create the Control Flow Graph in Fast or Accurate mode.
        if (analysisType == 'Fast'):
            cfg = project.analyses.CFG()
        elif (analysisType == 'Accurate'):#
            cfg = project.analyses.CFGAccurate()
        else:
            return

    except simuvex.SimSolverModeError:
        response['error'] = 'CFG generation failed because of SimSolverModeError'
        return json.dumps(response)
    except cle.errors.CLECompatibilityError:
        response['error'] = 'CFG generation failed because of unsupported format'
        return json.dumps(response)
    except AttributeError:
        response['error'] = 'See https://github.com/angr/angr/issues/288'
        return json.dumps(response)


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
