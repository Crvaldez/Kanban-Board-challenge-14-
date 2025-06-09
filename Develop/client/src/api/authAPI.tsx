import { UserLogin } from "../interfaces/UserLogin";

const login = async (userInfo: UserLogin) => {
  // TODO: make a POST request to the login route
  const response = await fetch("http://localhost:3000/api/auth/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(userInfo),
  });
  if (!response.ok) {
    throw new Error("Login failed");
  }
  const data = await response.json();
  if (!data.error){
    throw new Error(data.error);
  }
  return data;
  



export { login };
