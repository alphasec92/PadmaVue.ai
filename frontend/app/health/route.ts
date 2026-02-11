/**
 * Health check endpoint for Docker and orchestration
 * Returns a simple status response for health probes
 */
export async function GET() {
  return Response.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'padmavue-frontend'
  });
}
