import { type NextRequest, NextResponse } from "next/server";
import { getDb, initializeDatabase } from "@/lib/db";
import { createToken, setAuthCookie } from "@/lib/auth";
import bcrypt from "bcryptjs";

export async function POST(request: NextRequest) {
  try {
    initializeDatabase();
    const { name, email, password, phone } = await request.json();

    if (!name || !email || !password || !phone) {
      return NextResponse.json(
        { error: "Missing required fields" },
        { status: 400 }
      );
    }

    const db = getDb();
    const existingUser = db
      .prepare("SELECT id FROM users WHERE email = ?")
      .get(email);

    if (existingUser) {
      return NextResponse.json(
        { error: "Email already registered" },
        { status: 400 }
      );
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    const result = db
      .prepare(
        `
      INSERT INTO users (name, email, phone, password, role)
      VALUES (?, ?, ?, ?, ?)
    `
      )
      .run(name, email, phone, hashedPassword, "user");

    const userId = result.lastInsertRowid as number;
    const token = await createToken({
      id: userId,
      email,
      role: "user",
    });

    // Create a response and set the auth cookie explicitly on the response
    const response = NextResponse.json(
      { message: "Registration successful", userId },
      { status: 201 }
    );

    // Mirror login behavior: set cookie on the response so it is sent in production
    response.cookies.set("auth_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 7 * 24 * 60 * 60, // 7 days
    });

    console.log("[Register] Set auth cookie for userId:", userId);

    return response;
  } catch (error) {
    console.error("Registration error:", error);
    return NextResponse.json({ error: "Registration failed" }, { status: 500 });
  }
}
