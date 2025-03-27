import streamlit as st
import uuid
import requests

st.set_page_config(
    page_title="Elastic Search Chatbot",
    page_icon=":robot_face:",
    layout="centered",
    initial_sidebar_state="auto"
)

session_id = str(uuid.uuid4())
# url="https://74.249.58.8:5678/webhook-test/c9baa6dc-ac80-487f-ae55-718b06264cf8"
url = "https://74.249.58.8:5678/webhook/c9baa6dc-ac80-487f-ae55-718b06264cf8"

if "history" not in st.session_state:
    st.session_state.history = []


def send_message(message=None):
    # Use the message parameter if provided, otherwise use the session state input
    user_input = message or st.session_state.user_input

    if user_input.strip():
        body = {
            "sessionId": session_id,
            "chatInput": user_input,
            "action": "sendMessage"
        }
        res = requests.post(url, json=body, verify=False)

        if res.content:
            try:
                resp = res.json()
                st.session_state.history.append({
                    "question": user_input,
                    "answer": resp.get("output", "No response received")
                })
            except ValueError:
                st.session_state.history.append({
                    "question": user_input,
                    "answer": f"Error decoding JSON response: {res.text}"
                })
        else:
            st.session_state.history.append({
                "question": user_input,
                "answer": "Empty response from server"
            })

        # Clear the user input after sending
        st.session_state.user_input = ""

def quick_message_click(msg):
    send_message(msg)
st.title("Elastic Search ChatBot")

st.write("### Quick Messages")
quick_messages = [
    {
        'label': "Windows Failed Login Attempts & Account Lockouts",
        'prompt': """Analyze Windows security logs and generate a comprehensive report of all failed login attempts. Include details such as: total number of failed attempts, unique user accounts targeted, timestamps of attempts, source IP addresses, and any patterns indicating potential brute force attacks. Specifically identify:
        1. Number of distinct user accounts with failed login attempts
        2. Frequency of login failures per account
        3. Time windows with highest concentration of login failures
        4. Potential source locations or IP ranges of these attempts
        5. Recommend immediate security mitigation steps"""
    },
    {
        'label': "Retrieve top vulnerability threat",
        'prompt': """Conduct a thorough vulnerability assessment across all systems and networks. Provide a detailed analysis of the most critical security vulnerability, including:
        1. Specific vulnerability type (e.g., remote code execution, privilege escalation)
        2. Affected systems, software, and versions
        3. Current exploit probability and potential impact rating
        4. Specific CVE (Common Vulnerabilities and Erecorded vulnerabilities in the database based on the provided query. Please ensure that the systems and networks have been properly assessed and that the data is up to date. If you need further assistancexposures) number if applicable
        5. Recommended patch or mitigation strategy
        6. Potential attack vectors and exploitation methods"""
    },
    {
        'label': "Top 5 windows event ids",
        'prompt': """Generate a comprehensive report of the top 5 most significant Windows Event IDs across the network, including:
        1. Detailed description of each Event ID
        2. Frequency of occurrence
        3. Potential security implications
        4. Recommended action for each event type
        5. Contextual analysis of why these events are critical
        Example events to potentially include:
        - Security events (login attempts, account changes)
        - System startup/shutdown logs
        - Application error events
        - Audit failures
        - Critical system warnings"""
    },
    {
        'label': "Retrieve top vulnerable agent",
        'prompt': """Perform a comprehensive vulnerability assessment to identify the most vulnerable system or network agent. Provide an in-depth analysis including:
        1. Specific agent/system details (hostname, IP address, operating system)
        2. Comprehensive list of identified vulnerabilities
        3. Severity rating for each vulnerability
        4. Potential exploit mechanisms
        5. Current patch level and version information
        6. Recommended immediate remediation steps
        7. Comparative analysis with other network agents to understand relative risk"""
    },
    {
        'label': "Top failed SEA checks",
        'prompt': """Analyze Security Event Analyzer (SEA) logs to identify and report on the most critical failed security checks. Include:
        1. Specific failed security check details
        2. Number of failed check occurrences
        3. Systems or network segments affected
        4. Potential security implications of each failed check
        5. Immediate recommended actions
        6. Long-term strategy to address recurring security check failures
        7. Trend analysis of security check failures over time"""
    },
    {
        'label': "Top 10 source IPs in SSH failures",
        'prompt': """Conduct a detailed investigation of SSH login failures, focusing on source IP addresses. Generate a comprehensive report including:
        1. Ranking of top 10 source IP addresses with failed SSH attempts
        2. Geolocation information for each source IP
        3. Frequency and timing of login attempts
        4. Potential origin (country, organization, network)
        5. Types of SSH authentication failures
        6. Recommended IP blocking or additional security measures
        7. Correlation with known threat intelligence databases
        8. Pattern analysis of attack methodologies"""
    },
]

quick_message_container = st.container()
with quick_message_container:
    for i in range(0, len(quick_messages), 3):
        cols = st.columns(3)
        for j in range(3):
            if i + j < len(quick_messages):
                if cols[j].button(quick_messages[i + j]['label'], key=f"quick_msg_{i+j}"):
                    quick_message_click(quick_messages[i + j]['prompt'])

st.write("### Chat History")
for chat in st.session_state.history:
    with st.chat_message("user"):
        st.markdown(chat['question'])
    with st.chat_message("assistant"):
        st.markdown(chat["answer"])

st.sidebar.title("Chat History")
for i, chat in enumerate(st.session_state.history):
    with st.sidebar.expander(f"Chat {i+1}"):
        st.markdown(f"**You:** {chat['question']}")
        st.markdown(f"**Assistant:** {chat['answer']}")

user_input = st.text_input(
    "Type your question here...",
    key="user_input",
    placeholder="Ask me anything...",
    on_change=send_message
)
