
export default function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");

    return res.status(405).json({
      success: false,
      error: "Method not allowed"
    });
  }

  return res.status(200).json({
    success: true,
    service: "Bokkara Notifications",
    status: "operational",
    version: "1.0.0"
  });
}
