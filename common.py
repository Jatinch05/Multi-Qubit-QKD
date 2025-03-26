import math
import random

def logistic_map(x, r=3.9):
    """Apply the logistic map to introduce chaos."""
    return r * x * (1 - x)

def chaotic_angle(x):
    """Map chaotic output to an angle between 0 and π/2."""
    return x * (math.pi / 2)

def generate_chaotic_angles(num_pairs, x0=None, r=3.9):
    """Generate a list of chaotic angles for multi-qubit QKD."""
    if x0 is None:
        x0 = random.random()
    angles = []
    x = x0
    for i in range(num_pairs):
        x = logistic_map(x, r)
        angles.append(chaotic_angle(x))
    return angles
