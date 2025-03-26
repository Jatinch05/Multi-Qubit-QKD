from qiskit import QuantumCircuit
from common import generate_chaotic_angles

def prepare_bell_state_with_chaos(angle):
    """
    Create a Bell state (entangled qubit pair) and apply a chaotic rotation
    on qubit 0 using the provided angle.
    """
    qc = QuantumCircuit(2, 2)
    qc.h(0)
    qc.cx(0, 1)
    qc.ry(angle, 0)
    return qc

def alice_generate_qubits(num_pairs):
    """
    Generate a list of quantum circuits (each representing an entangled pair)
    with chaotic rotations based on generated chaotic angles.
    """
    chaotic_angles = generate_chaotic_angles(num_pairs)
    circuits = [prepare_bell_state_with_chaos(angle) for angle in chaotic_angles]
    return circuits, chaotic_angles
