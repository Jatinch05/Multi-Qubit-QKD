from qiskit import QuantumCircuit

def bob_measure_circuit(qc):
    """
    Bob measures both qubits in the computational basis.
    """
    qc.measure(0, 0)
    qc.measure(1, 1)
    return qc
