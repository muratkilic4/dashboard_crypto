// Supabase Edge Function: username-reminder
// Required secrets: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, RESEND_API_KEY, MAIL_FROM
// Deploy with JWT verification disabled because this is called before login.
// Add rate limiting / CAPTCHA before exposing this endpoint to a large public audience.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }

  try {
    const body = await req.json();
    const email = String(body?.email || "").trim().toLowerCase();
    if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return new Response(JSON.stringify({ success: true }), {
        status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const resendKey = Deno.env.get("RESEND_API_KEY");
    const mailFrom = Deno.env.get("MAIL_FROM");
    if (!supabaseUrl || !serviceRoleKey || !resendKey || !mailFrom) {
      console.error("Missing required Edge Function secrets.");
      return new Response(JSON.stringify({ error: "Recovery service is not configured." }), {
        status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    let matchedUser: { id: string; email?: string } | null = null;
    for (let page = 1; page <= 10; page++) {
      const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 1000 });
      if (error) throw error;
      const users = data.users || [];
      matchedUser = users.find((u) => (u.email || "").toLowerCase() === email) || null;
      if (matchedUser || users.length < 1000) break;
    }

    if (matchedUser) {
      const { data: profile, error } = await admin
        .from("profiles")
        .select("username")
        .eq("user_id", matchedUser.id)
        .maybeSingle();
      if (error) throw error;

      if (profile?.username) {
        const response = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${resendKey}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            from: mailFrom,
            to: [email],
            subject: "CryptoDash Pro kullanıcı adı hatırlatma",
            text: `Merhaba, CryptoDash Pro kullanıcı adın: ${profile.username}\n\nBu isteği sen yapmadıysan bu e-postayı yok sayabilirsin.`,
          }),
        });
        if (!response.ok) {
          console.error("Resend send failed:", response.status, await response.text());
          throw new Error("Could not send reminder email.");
        }
      }
    }

    // Always return the same public response to reduce account enumeration.
    return new Response(JSON.stringify({ success: true }), {
      status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error("username-reminder error:", error);
    return new Response(JSON.stringify({ error: "Reminder could not be sent." }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
