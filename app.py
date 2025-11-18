import streamlit as st
import pandas as pd
import traceback

from markov_model.pipeline import analyze_paths

st.set_page_config(
    page_title="Malicious Process Path Detection",
    layout="wide"
)

# -----------------------------------------------------------------------------------
# Title & Description
# -----------------------------------------------------------------------------------

st.title("🔍 Malicious Process Path Detection Dashboard")
st.write("""
Upload a CSV file containing process logs (Sysmon, Defender, or custom format).
The system will apply your **Context-Aware Weighted Markov Chain model** to detect
statistically unusual or risky process paths.
""")

# -----------------------------------------------------------------------------------
# File Upload
# -----------------------------------------------------------------------------------

uploaded_file = st.file_uploader("Upload a CSV log file", type=["csv"])

if not uploaded_file:
    st.info("Please upload a CSV file to begin analysis.")
    st.stop()

# -----------------------------------------------------------------------------------
# Load Data
# -----------------------------------------------------------------------------------

try:
    data = pd.read_csv(uploaded_file)
except Exception as e:
    st.error("❌ Failed to read CSV file. Make sure it's valid.")
    st.code(traceback.format_exc())
    st.stop()

st.subheader("📄 Raw Data Preview")
st.dataframe(data.head(50), height=300)

# -----------------------------------------------------------------------------------
# Run Analysis
# -----------------------------------------------------------------------------------

st.subheader("⚙️ Running Markov Chain Analysis...")

with st.spinner("Computing transitions, probabilities, and threat scores..."):
    try:
        results = analyze_paths(data)
    except Exception as e:
        st.error("❌ Error while running the analysis pipeline.")
        st.code(traceback.format_exc())
        st.stop()

st.success("Analysis completed!")

# -----------------------------------------------------------------------------------
# Results Table
# -----------------------------------------------------------------------------------

st.subheader("🔥 Suspicious Process Paths (Ranked by Threat Score)")
st.write("""
Each row represents an analyzed process chain.  
Threat score is calculated using:
- Transition rarity (Markov probability)  
- Contextual risk weighting  
- Composite scoring  
""")

st.dataframe(
    results.sort_values("threat_score", ascending=False).head(50),
    use_container_width=True,
    height=400
)

# -----------------------------------------------------------------------------------
# Threat Score Plot
# -----------------------------------------------------------------------------------

st.subheader("📊 Top 15 Threat Scores")

try:
    st.bar_chart(
        results.sort_values("threat_score", ascending=False)
        .head(15)
        .set_index("path")["threat_score"]
    )
except:
    st.warning("Could not create chart due to missing 'path' or 'threat_score' fields.")

# -----------------------------------------------------------------------------------
# Optional: Show Process Graph
# -----------------------------------------------------------------------------------

st.subheader("🧬 Process Tree Graph (Optional Visualisation)")

st.write("""
Select a process path below to visualise it as a graph.
""")

if "path" in results.columns:
    selected_path = st.selectbox(
        "Choose a process path",
        results["path"].tolist()
    )

    if st.button("Render Graph"):
        try:
            import networkx as nx
            import matplotlib.pyplot as plt

            G = nx.DiGraph()

            processes = selected_path.split(" → ")

            # Add nodes with basic incremental threat color
            for i, p in enumerate(processes):
                G.add_node(p)

                if i < len(processes) - 1:
                    G.add_edge(processes[i], processes[i+1])

            fig, ax = plt.subplots(figsize=(10, 5))
            pos = nx.spring_layout(G, seed=42)
            nx.draw(G, pos, with_labels=True, node_size=2500, font_size=10)
            st.pyplot(fig)

        except Exception as e:
            st.error("❌ Could not render graph.")
            st.code(traceback.format_exc())
else:
    st.info("Column 'path' not found — graph visualisation skipped.")

# -----------------------------------------------------------------------------------
# Finish
# -----------------------------------------------------------------------------------

st.markdown("---")
st.write("Made for the Master Thesis project **Context-Aware Weighted Markov Chains for Detecting Malicious Process Paths**")
