from pgadmin.utils.ajax import make_json_response
from pgadmin.tools.sqleditor.utils.start_running_query import StartRunningQuery
from pgadmin.tools.sqleditor import check_transaction_status

def start_query_tool_session():
    trans_id = str(secrets.choice(range(1, 9999999)))
    session_obj = {}  # Initialize session object
    trans_obj = {}  # Initialize transaction object

    # Save transaction in session
    StartRunningQuery.save_transaction_in_session(session_obj, trans_id, trans_obj)
    return trans_id


def execute_query_with_trans_id(trans_id, sql):
    # Retrieve session information
    session_obj = StartRunningQuery.retrieve_session_information(session, trans_id)
    
    if isinstance(session_obj, Response):
        return session_obj

    trans_obj = pickle.loads(session_obj['command_obj'])
    conn = get_connection(trans_obj.sid)  # Function to get connection

    # Execute the query
    conn.execute_async(sql)

def check_trans_status(trans_id):
    status, error_msg, conn, trans_obj, session_obj = check_transaction_status(trans_id)
    if not status:
        return error_msg
    return conn.transaction_status()


start_query_tool_session
