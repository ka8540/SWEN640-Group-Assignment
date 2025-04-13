import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from scipy.stats import spearmanr

# Load the CSV
df = pd.read_csv("repo_data.csv")

# Check for required columns
if 'bugs_exploited' in df.columns and 'age_years' in df.columns:
    # Calculate Spearman correlation
    corr, p_value = spearmanr(df['age_years'], df['bugs_exploited'])

    # Plot with regression line
    plt.figure(figsize=(10, 6))
    sns.regplot(
        x='age_years',
        y='bugs_exploited',
        data=df,
        scatter_kws={"s": 50},
        line_kws={"color": "red"},
        ci=None
    )

    plt.title(f"Spearman Correlation: {corr:.2f} (p-value: {p_value:.4f})")
    plt.xlabel('Repository Age (Years)')
    plt.ylabel('Number of Bugs (CVEs)')
    plt.grid(True)
    plt.tight_layout()

    # Save the plot
    plt.savefig("spearman_correlation_plot.png")
    # plt.show()  # Uncomment this to show plot in window
else:
    print("Required columns 'age_years' and 'bugs_exploited' not found in CSV.")
