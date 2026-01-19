# app.py
import os
import streamlit as st
import time

from report_builder import load_json_from_text, generate_pdf_bytes

st.set_page_config(page_title="RB Cyber Health Check", layout="wide")

# Optional: show logo in the app UI
# Always use this bundled logo file
RB_LOGO_PATH = os.path.join("RB_logo.jpg")
if not os.path.exists(RB_LOGO_PATH):
    st.error("RB logo not found. Please add it at: assets/RB_logo.jpg")
    st.stop()
st.image(RB_LOGO_PATH, width=220)
st.title("RB Cyber Health Check Report Generator")



with st.sidebar:
    st.header("Report Inputs")
    business_name = st.text_input("Business name", value="TBD")
    email = st.text_input("Email", value="TBD")
    website = st.text_input("Website", value="TBD")
    classification = st.selectbox("Classification", ["Confidential", "Internal", "Public"], index=0)
    last_reviewed = st.text_input("Last Reviewed (DD/MM/YYYY)", value="")

st.subheader("Upload Data Files")
col1, col2 = st.columns(2)

with col1:
    hibp_file = st.file_uploader(("HIBP data"), type=["txt", "json"])
with col2:
    ssl_file = st.file_uploader(("SSL Labs Data"), type=["txt", "json"])

if hibp_file and ssl_file:
    try:
        hibp_text = hibp_file.read().decode("utf-8", errors="replace")
        ssl_text = ssl_file.read().decode("utf-8", errors="replace")

        hibp = load_json_from_text(hibp_text)
        ssl = load_json_from_text(ssl_text)

        st.success("Files parsed successfully.")

        #with st.expander("Preview parsed HIBP JSON"):
            #st.json(hibp)

        #with st.expander("Preview parsed SSL Labs JSON"):
            #st.json(ssl)

        if st.button("Generate PDF Report"):
             with st.spinner("🔐 AI is analysing your data and generating the Cyber Health Check report..."):
                time.sleep(3)  # simulate AI processing time
         
   
            

    
            pdf_bytes = generate_pdf_bytes(
                    business_name=business_name.strip() or "TBD",
                    email=email.strip() or "TBD",
                    website=website.strip() or "TBD",
                    hibp=hibp,
                    ssl=ssl,
                    classification=classification,
                    last_reviewed=last_reviewed.strip() or None,
                    logo_path=RB_LOGO_PATH,  # <-- always RB_logo.jpg
            )
            
            st.success("📄 Your Cyber Health Check Report is ready to download")
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
