import os
import streamlit as st

from report_builder import load_json_from_text, generate_pdf_bytes

st.set_page_config(page_title="RB Cyber Health Check", layout="wide")
st.title("RB Cyber Health Check Report Generator")

# Put your logo in your repo at: assets/RB_logo.jpg
DEFAULT_LOGO_PATH = os.path.join("assets", "RB_logo.jpg")

with st.sidebar:
    st.header("Report Inputs")
    business_name = st.text_input("Business name", value="TBD")
    email = st.text_input("Email", value="TBD")
    website = st.text_input("Website", value="TBD")
    classification = st.selectbox("Classification", ["Confidential", "Internal", "Public"], index=0)
    last_reviewed = st.text_input("Last Reviewed (DD/MM/YYYY)", value="")

    st.divider()
    st.subheader("Logo")
    st.caption("Default: assets/RB_logo.jpg (used top-left on every page).")

    use_default_logo = st.checkbox("Use bundled RB logo", value=True)
    uploaded_logo = st.file_uploader("Or upload a logo (optional)", type=["png", "jpg", "jpeg"])

logo_path = None
if use_default_logo and os.path.exists(DEFAULT_LOGO_PATH):
    logo_path = DEFAULT_LOGO_PATH

if uploaded_logo is not None:
    import tempfile

    suffix = "." + uploaded_logo.name.split(".")[-1].lower()
    fd, tmp_path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    with open(tmp_path, "wb") as f:
        f.write(uploaded_logo.getbuffer())
    logo_path = tmp_path  # overrides default

st.subheader("Upload Data Files")
col1, col2 = st.columns(2)

with col1:
    hibp_file = st.file_uploader("ihbp_data.txt (HIBP extract)", type=["txt", "json"])
with col2:
    ssl_file = st.file_uploader("ssl_labs_data.txt (SSL Labs extract)", type=["txt", "json"])

if hibp_file and ssl_file:
    try:
        hibp_text = hibp_file.read().decode("utf-8", errors="replace")
        ssl_text = ssl_file.read().decode("utf-8", errors="replace")

        hibp = load_json_from_text(hibp_text)
        ssl = load_json_from_text(ssl_text)

        st.success("Files parsed successfully.")

        with st.expander("Preview parsed HIBP JSON"):
            st.json(hibp)

        with st.expander("Preview parsed SSL Labs JSON"):
            st.json(ssl)

        if st.button("Generate PDF Report"):
            pdf_bytes = generate_pdf_bytes(
                business_name=business_name.strip() or "TBD",
                email=email.strip() or "TBD",
                website=website.strip() or "TBD",
                hibp=hibp,
                ssl=ssl,
                classification=classification,
                last_reviewed=last_reviewed.strip() or None,
                logo_path=logo_path,  # <-- RB logo top-left on every page
            )

            st.download_button(
                "Download Report (PDF)",
                data=pdf_bytes,
                file_name=f"Cyber_Health_Check_Report_{(business_name or 'TBD').replace(' ', '_')}.pdf",
                mime="application/pdf",
            )

    except Exception as e:
        st.error(f"Failed to parse/generate report: {e}")
else:
    st.info("Upload both files to enable report generation.")
