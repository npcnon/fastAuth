import httpx

async def fetch_public_employee_data(api_url, employee_id):
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{api_url}")  
        if response.status_code == 200:
            data = response.json()  
            for employee in data:
                # print(f"employee role: {employee.get("role")}")
                if employee.get("employee_id") == int(employee_id):
                    return extract_user_details(employee)
            raise ValueError(f"Identifier {employee_id} not found in public API.")
        elif response.status_code == 404:
            raise ValueError(f"API endpoint not found (404).")
        else:
            response.raise_for_status()

def extract_user_details(user_data):
    necessary_details = {
        "employee_id": user_data.get("employee_id"),
        "role": user_data.get("role"),
        "first_name":user_data.get("firstName"),
        "last_name":user_data.get("lastName"),
        "fullName": user_data.get("fullName"),
        "campus_id": user_data.get("campus_id"),
        "gender": user_data.get("gender"),
    }
    if user_data.get("middleName"):
        necessary_details["middle_name"] = user_data.get("middleName")

    if user_data.get("department") and user_data["department"].get("departmentCode"):
        necessary_details["departmentCode"] = user_data["department"]["departmentCode"]
    
    if user_data.get("isActive") == True:
        return necessary_details
    else:
        return None