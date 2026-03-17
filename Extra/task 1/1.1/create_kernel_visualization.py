"""
Create correct 3x3 kernel visualization for CNN documentation
Author: Levan Kalatozishvili
"""

import matplotlib.pyplot as plt
import numpy as np
import os

# Create task_1 directory if it doesn't exist
os.makedirs('task_1', exist_ok=True)

# Create the correct 3x3 kernel visualization
fig = plt.figure(figsize=(14, 6))

# LEFT: Show 3x3 kernel with 9 weights
ax1 = plt.subplot(1, 2, 1)
kernel = np.array([
    [1, 0, -1],
    [2, 0, -2],
    [1, 0, -1]
])

im = ax1.imshow(kernel, cmap='RdBu', vmin=-2, vmax=2)
ax1.set_title('CORRECT: 3×3 Convolutional Kernel\n(9 weights total)',
             fontsize=13, fontweight='bold')

# Add grid
for i in range(4):
    ax1.axhline(i-0.5, color='black', linewidth=2)
    ax1.axvline(i-0.5, color='black', linewidth=2)

# Label each weight
for i in range(3):
    for j in range(3):
        weight = kernel[i, j]
        color = 'white' if abs(weight) > 1 else 'black'
        ax1.text(j, i, f'w{i*3+j+1}\n({weight})',
                ha='center', va='center',
                color=color, fontsize=14, fontweight='bold')

ax1.set_xticks([0, 1, 2])
ax1.set_yticks([0, 1, 2])
ax1.set_xticklabels(['col 0', 'col 1', 'col 2'])
ax1.set_yticklabels(['row 0', 'row 1', 'row 2'])
plt.colorbar(im, ax=ax1, fraction=0.046)

# RIGHT: Show how convolution works
ax2 = plt.subplot(1, 2, 2)
ax2.axis('off')
ax2.set_title('How 3×3 Convolution Works', fontsize=13, fontweight='bold')

explanation = """
KERNEL STRUCTURE:
┌───────────────┐
│  w₁  w₂  w₃  │     Each cell = 1 weight
│  w₄  w₅  w₆  │     Total = 9 weights
│  w₇  w₈  w₉  │
└───────────────┘

CONVOLUTION OPERATION:
  Input (5×5)        Kernel (3×3)      Output (3×3)
┌─────────────┐    ┌─────────┐      ┌─────────┐
│ x₁ x₂ x₃ .. │    │ w₁ w₂ w₃│      │ y₁ y₂ y₃│
│ x₄ x₅ x₆ .. │  ⊗ │ w₄ w₅ w₆│  =   │ y₄ y₅ y₆│
│ x₇ x₈ x₉ .. │    │ w₇ w₈ w₉│      │ y₇ y₈ y₉│
│  .. .. .. .. │    └─────────┘      └─────────┘
└─────────────┘

Formula:
y = Σᵢ Σⱼ (xᵢⱼ × wᵢⱼ)

Example (first output):
y₁ = x₁w₁ + x₂w₂ + x₃w₃ +
     x₄w₄ + x₅w₅ + x₆w₆ +
     x₇w₇ + x₈w₈ + x₉w₉

NOTE: Common confusion
X 3×3 kernel ≠ 36 weights
✓ 3×3 kernel = 9 weights

For RGB images (3 channels):
  3×3×3 = 27 weights per kernel
"""

ax2.text(0.1, 0.5, explanation, fontsize=10, family='monospace',
        verticalalignment='center', transform=ax2.transAxes,
        bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.3))

plt.tight_layout()
plt.savefig('task_1/kernel_correct.png', dpi=300, bbox_inches='tight')
print("✓ Created: task_1/kernel_correct.png")
plt.show()

print("\nVisualization complete!")
print("File saved to: task_1/kernel_correct.png")