# app.py
import streamlit as st
import gspread
import pandas as pd
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime

# -----------------------
# CONFIG
# -----------------------
SHEET_ID = "1dO7a3evLEu7ONM5NQ1L7IQBt60xXJmsvvo0SS6rWZic"  # Replace with your Sheet ID
SERVICE_ACCOUNT_FILE = "service_account.json"

# -----------------------
# Google Sheets setup
# -----------------------
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
creds = ServiceAccountCredentials.from_json_keyfile_name(SERVICE_ACCOUNT_FILE, scope)
client = gspread.authorize(creds)
spreadsheet = client.open_by_key(SHEET_ID)

# -----------------------
# Expected sheets and headers
# -----------------------
sheets_info = {
    "users": ["username", "password", "role", "email", "phone"],
    "students": ["username", "name", "department", "email", "phone", "attendance_percentage",
                 "tution_fee_status", "hostel_fee_status", "exam_fee_status", "transport_fee_status",
                 "books_issued", "hostel_room"],
    "faculty": ["username", "name", "department", "email", "phone"],
    "requests": ["username", "role", "request_type", "details", "status", "timestamp"],
    "payments": ["username", "fee_type", "amount", "date", "status"],
    "notifications": ["notification", "date"],
    "recent_activity": ["username", "role", "action", "timestamp"]
}

# -----------------------
# Create worksheets if missing
# -----------------------
worksheet_objs = {}
for name, header in sheets_info.items():
    try:
        ws = spreadsheet.worksheet(name)
        try:
            first_row = ws.row_values(1)
            if not first_row:
                ws.insert_row(header, index=1)
        except Exception:
            try:
                ws.insert_row(header, index=1)
            except Exception:
                pass
    except gspread.exceptions.WorksheetNotFound:
        ws = spreadsheet.add_worksheet(title=name, rows=500, cols=20)
        try:
            ws.insert_row(header, index=1)
        except Exception:
            pass
    worksheet_objs[name] = ws


def ws_by_name(n):
    return worksheet_objs[n]


# -----------------------
# Session cache & utilities
# -----------------------
if "cache" not in st.session_state:
    st.session_state.cache = {}
if "force_rerun" not in st.session_state:
    st.session_state.force_rerun = False


def safe_get_all_records(ws, sheet_name):
    try:
        records = ws.get_all_records()
        if not records:
            return pd.DataFrame(columns=sheets_info[sheet_name])
        return pd.DataFrame(records)
    except gspread.exceptions.APIError:
        st.warning(f"Quota exceeded while reading {sheet_name}, using cached/empty data.")
        return pd.DataFrame(columns=sheets_info[sheet_name])
    except Exception as e:
        st.session_state.cache.setdefault("_errors", []).append(f"Error reading {sheet_name}: {e}")
        return pd.DataFrame(columns=sheets_info[sheet_name])


def load_all_once():
    for name in sheets_info.keys():
        if name not in st.session_state.cache:
            st.session_state.cache[name] = safe_get_all_records(ws_by_name(name), name)


def refresh_single(name):
    st.session_state.cache[name] = safe_get_all_records(ws_by_name(name), name)
    return st.session_state.cache[name]


def append_row(name, row):
    ws = ws_by_name(name)
    try:
        ws.append_row(row)
        df = st.session_state.cache.get(name)
        if df is None or df.empty:
            st.session_state.cache[name] = pd.DataFrame([row], columns=sheets_info[name])
        else:
            new_row_df = pd.DataFrame([row], columns=df.columns)
            st.session_state.cache[name] = pd.concat([df, new_row_df], ignore_index=True)
    except gspread.exceptions.APIError:
        df = st.session_state.cache.get(name)
        if df is None or df.empty:
            st.session_state.cache[name] = pd.DataFrame([row], columns=sheets_info[name])
        else:
            new_row_df = pd.DataFrame([row], columns=df.columns)
            st.session_state.cache[name] = pd.concat([df, new_row_df], ignore_index=True)


def update_cell(name, df_index, col_name, new_value):
    df = st.session_state.cache.get(name)
    if df is None:
        refresh_single(name)
        df = st.session_state.cache.get(name)
    if col_name not in df.columns:
        raise KeyError(f"Column {col_name} not in {name}")
    sheet_row = int(df_index) + 2
    sheet_col = df.columns.get_loc(col_name) + 1
    ws = ws_by_name(name)
    try:
        ws.update_cell(sheet_row, sheet_col, new_value)
        st.session_state.cache[name].at[df_index, col_name] = new_value
    except gspread.exceptions.APIError:
        st.warning(f"Quota exceeded, updated {name} cell only in local cache.")
        st.session_state.cache[name].at[df_index, col_name] = new_value


def delete_user(username):
    df = st.session_state.cache.get("users")
    if df is None or df.empty:
        refresh_single("users")
        df = st.session_state.cache.get("users")
    idx = find_row_index_by_key("users", "username", username)
    if idx is not None:
        ws = ws_by_name("users")
        try:
            ws.delete_row(idx + 2)
        except gspread.exceptions.APIError:
            st.warning(f"Quota exceeded, user deleted only in local cache.")
        st.session_state.cache["users"].drop(index=idx, inplace=True)
        st.session_state.cache["users"].reset_index(drop=True, inplace=True)
        log_activity_local(st.session_state.user, st.session_state.role, f"Deleted user {username}")
        st.session_state.force_rerun = not st.session_state.force_rerun
        st.success(f"User '{username}' deleted.")


def find_row_index_by_key(name, key_col, key_value):
    df = st.session_state.cache.get(name)
    if df is None:
        refresh_single(name)
        df = st.session_state.cache.get(name)
    if df is None or df.empty:
        return None
    matches = df[df[key_col].astype(str).str.strip().str.lower() == str(key_value).strip().lower()]
    if matches.empty:
        return None
    return matches.index[0]


def log_activity_local(user, role, action):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    append_row("recent_activity", [user, role, action, ts])


# -----------------------
# Load all sheets once
# -----------------------
load_all_once()

# -----------------------
# Demo data
# -----------------------
def ensure_demo_data():
    users_df = st.session_state.cache.get("users")
    demo_users = [
        ["admin", "pass123", "Admin", "admin@example.com", "999000501"],
        ["student1", "pass123", "Student", "student1@example.com", "999000111"],
        ["student2", "pass123", "Student", "student2@example.com", "999000112"],
        ["librarian", "pass123", "Librarian", "lib@example.com", "999000301"],
        ["warden", "pass123", "Hostel Warden", "warden@example.com", "999000401"],
    ]
    existing = []
    if users_df is not None and not users_df.empty:
        existing = users_df["username"].astype(str).str.strip().str.lower().tolist()
    for r in demo_users:
        if r[0].strip().lower() not in existing:
            append_row("users", r)


ensure_demo_data()

# -----------------------
# Authentication
# -----------------------
def authenticate(username, password):
    users = st.session_state.cache.get("users")
    if users is None or users.empty:
        refresh_single("users")
        users = st.session_state.cache.get("users")
    uname = str(username).strip().lower()
    pwd = str(password).strip()
    users["username_norm"] = users["username"].astype(str).str.strip().str.lower()
    users["password"] = users["password"].astype(str).str.strip()
    matched = users[(users["username_norm"] == uname) & (users["password"] == pwd)]
    if not matched.empty:
        row = matched.iloc[0]
        return row["role"], row["username"]
    return None, None


# -----------------------
# Streamlit UI
# -----------------------
st.set_page_config(page_title="EcoOne ERP", layout="wide")
st.title("EcoOne ERP Prototype")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.role = None

menu = ["Login", "Sign Up"]
choice = st.sidebar.selectbox("Menu", menu)

# -----------------------
# Sign Up
# -----------------------
if choice == "Sign Up":
    st.subheader("Create Account")
    su_username = st.text_input("Username", key="su_username")
    su_password = st.text_input("Password", type="password", key="su_password")
    su_role = st.selectbox("Role", ["Student", "Faculty", "Librarian", "Hostel Warden", "Admin"], key="su_role")
    su_email = st.text_input("Email", key="su_email")
    su_phone = st.text_input("Phone", key="su_phone")
    if st.button("Create Account", key="create_account"):
        users = st.session_state.cache.get("users")
        if su_username.strip().lower() in users["username"].astype(str).str.strip().str.lower().values:
            st.error("Username exists.")
        else:
            append_row("users", [su_username.strip(), su_password.strip(), su_role, su_email.strip(), su_phone.strip()])
            st.success("Account created.")


# -----------------------
# Login
# -----------------------
elif choice == "Login":
    st.subheader("Login")
    li_username = st.text_input("Username", key="login_username")
    li_password = st.text_input("Password", type="password", key="login_password")
    if st.button("Login", key="login_btn"):
        role, canon_user = authenticate(li_username, li_password)
        if role:
            st.session_state.logged_in = True
            st.session_state.user = canon_user
            st.session_state.role = role
            log_activity_local(canon_user, role, "Logged in")
            st.session_state.force_rerun = not st.session_state.force_rerun
        else:
            st.error("Invalid username/password")


# -----------------------
# Post-login dashboards
# -----------------------
if st.session_state.logged_in:
    user = st.session_state.user
    role = st.session_state.role
    st.sidebar.markdown(f"**Logged in as:** {user} ({role})")
    if st.sidebar.button("Logout", key="logout_btn"):
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.role = None
        st.session_state.force_rerun = not st.session_state.force_rerun

    # -----------------------
    # Admin Dashboard
    # -----------------------
    if role == "Admin":
        st.subheader("Admin Dashboard")
        tabs = st.tabs(["Overview", "Manage Users", "Recent Activity"])

        with tabs[0]:
            users_df = st.session_state.cache.get("users", pd.DataFrame(columns=sheets_info["users"]))
            students_df = st.session_state.cache.get("students", pd.DataFrame(columns=sheets_info["students"]))
            payments_df = st.session_state.cache.get("payments", pd.DataFrame(columns=sheets_info["payments"]))

            total_students = 0
            if not users_df.empty:
                total_students = users_df[
                    users_df["role"].astype(str).str.strip().str.lower() == "student"
                ].shape[0]

            pending_students = pd.DataFrame()
            if not students_df.empty:
                fee_cols = [col for col in students_df.columns if "fee_status" in col.lower()]
                if fee_cols:
                    students_df["has_pending"] = students_df[fee_cols].apply(
                        lambda row: any("pending" in str(x).lower() for x in row), axis=1
                    )
                    pending_students = students_df[students_df["has_pending"] == True]

            pending_count = pending_students.shape[0]
            total_payments = len(payments_df) if not payments_df.empty else 0

            col1, col2, col3 = st.columns(3)
            col1.metric("Total Students", total_students)
            col2.metric("Total Payments Recorded", total_payments)
            col3.metric("Students with Pending Fees", pending_count)

            if not pending_students.empty:
                st.markdown("### Students with Pending Fees")
                show_cols = [c for c in
                             ["name", "department", "tution_fee_status", "hostel_fee_status", "exam_fee_status",
                              "transport_fee_status"] if c in pending_students.columns]
                display_df = pending_students[show_cols].reset_index(drop=True)
                st.dataframe(display_df)
            else:
                st.info("✅ All students have cleared their fees.")

        with tabs[1]:
            st.markdown("### Users")
            users_df = st.session_state.cache.get("users", pd.DataFrame())
            st.dataframe(users_df.fillna(""))

            st.markdown("#### Add User")
            uu = st.text_input("Username", key="admin_user_add")
            upw = st.text_input("Password", type="password", key="admin_user_pass")
            urole = st.selectbox("Role",
                                 ["Student", "Faculty", "Librarian", "Hostel Warden", "Admin"],
                                 key="admin_user_role")
            if st.button("Add User", key="admin_user_add_btn"):
                append_row("users", [uu, upw, urole, "", ""])
                refresh_single("users")
                st.session_state.force_rerun = not st.session_state.force_rerun
                st.success("User added.")

            st.markdown("#### Delete User")
            del_user = st.selectbox(
                "Select User to Delete",
                users_df["username"].tolist() if not users_df.empty else [],
                key="del_user",
            )
            if st.button("Delete User", key="del_user_btn"):
                delete_user(del_user)

        with tabs[2]:
            st.markdown("### Recent Activity")
            recent_df = st.session_state.cache.get("recent_activity", pd.DataFrame())
            st.dataframe(recent_df.fillna(""))

    # -----------------------
    # Student Dashboard
    # -----------------------
    elif role == "Student":
        st.subheader("Student Dashboard")
        students = st.session_state.cache.get("students", pd.DataFrame())
        idx = find_row_index_by_key("students", "username", user)
        if idx is not None:
            row = students.loc[idx]
            st.write("**Personal Info**")
            st.write(row[["name", "department", "email", "phone"]])
            st.write("**Fees Status**")
            st.write(row[["tution_fee_status", "hostel_fee_status", "exam_fee_status", "transport_fee_status"]])
            st.write("**Books Issued:**", row.get("books_issued", ""))
            st.write("**Hostel Room:**", row.get("hostel_room", ""))

            st.subheader("Submit Requests")
            req_type = st.selectbox("Request Type", ["Library", "Hostel"], key="stu_req_type")
            details = st.text_input("Details", key="stu_req_details")
            if st.button("Submit Request", key="submit_req_btn"):
                if details.strip():
                    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    append_row("requests", [user, role, req_type, details.strip(), "Pending", ts])
                    st.success(f"{req_type} request submitted successfully.")
                    log_activity_local(user, role, f"Submitted {req_type} request: {details.strip()}")
                    refresh_single("requests")
                else:
                    st.error("Please enter request details.")

    # -----------------------
    # Librarian Dashboard
    # -----------------------
    elif role == "Librarian":
        st.subheader("Librarian Dashboard")
        reqs = st.session_state.cache.get("requests", pd.DataFrame())
        pending_lib = reqs[(reqs["request_type"] == "Library") & (reqs["status"] == "Pending")]
        st.markdown("### Pending Library Requests")
        if not pending_lib.empty:
            for i, r in pending_lib.iterrows():
                st.write(f"{r['username']} | {r['details']}")
                c1, c2 = st.columns(2)
                with c1:
                    if st.button(f"Approve_{i}", key=f"lib_app_{i}"):
                        update_cell("requests", i, "status", "Approved")
                        sidx = find_row_index_by_key("students", "username", r["username"])
                        if sidx is not None:
                            cur = st.session_state.cache["students"].at[sidx, "books_issued"]
                            new_val = (str(cur) + "," + str(r["details"])).strip(",") if cur else r["details"]
                            update_cell("students", sidx, "books_issued", new_val)
                        log_activity_local(user, role, f"Approved library request {r['username']}")
                        st.session_state.force_rerun = not st.session_state.force_rerun
                with c2:
                    if st.button(f"Reject_{i}", key=f"lib_rej_{i}"):
                        update_cell("requests", i, "status", "Rejected")
                        log_activity_local(user, role, f"Rejected library request {r['username']}")
                        st.session_state.force_rerun = not st.session_state.force_rerun
        else:
            st.info("No pending library requests")

        st.markdown("### Assigned Books Overview")
        students = st.session_state.cache.get("students", pd.DataFrame())
        assigned_books = students[students["books_issued"].notna() & (students["books_issued"] != "")]
        if not assigned_books.empty:
            st.dataframe(assigned_books[["name", "department", "books_issued"]])
        else:
            st.info("No books assigned yet.")

    # -----------------------
    # Hostel Warden Dashboard
    # -----------------------
    elif role == "Hostel Warden":
        st.subheader("Hostel Warden Dashboard")
        reqs = st.session_state.cache.get("requests", pd.DataFrame())
        pending_hostel = reqs[(reqs["request_type"] == "Hostel") & (reqs["status"] == "Pending")]
        st.markdown("### Pending Hostel Requests")
        if not pending_hostel.empty:
            for i, r in pending_hostel.iterrows():
                st.write(f"{r['username']} | {r['details']}")
                c1, c2 = st.columns(2)
                with c1:
                    if st.button(f"ApproveH_{i}", key=f"host_app_{i}"):
                        update_cell("requests", i, "status", "Approved")
                        sidx = find_row_index_by_key("students", "username", r["username"])
                        assigned = r["details"] if any(ch.isdigit() for ch in r["details"]) else "Assigned-" + datetime.now().strftime("%Y%m%d%H%M%S")
                        if sidx is not None:
                            update_cell("students", sidx, "hostel_room", assigned)
                        log_activity_local(user, role, f"Approved hostel request {r['username']}")
                        st.session_state.force_rerun = not st.session_state.force_rerun
                with c2:
                    if st.button(f"RejectH_{i}", key=f"host_rej_{i}"):
                        update_cell("requests", i, "status", "Rejected")
                        log_activity_local(user, role, f"Rejected hostel request {r['username']}")
                        st.session_state.force_rerun = not st.session_state.force_rerun
        else:
            st.info("No pending hostel requests")

        st.markdown("### Assigned Hostel Rooms Overview")
        students = st.session_state.cache.get("students", pd.DataFrame())
        assigned_rooms = students[students["hostel_room"].notna() & (students["hostel_room"] != "")]
        if not assigned_rooms.empty:
            st.dataframe(assigned_rooms[["name", "department", "hostel_room"]])
        else:
            st.info("No hostel rooms assigned yet.")
