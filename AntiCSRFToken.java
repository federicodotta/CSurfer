package burp;

import java.io.PrintWriter;

public class AntiCSRFToken 
{
	public String tokenValue;
	public String sessionID;
	private boolean isTokenBeingUsed;
	private static final int MAX_LOCK_RETRIES = 2000;
	private static final long SLEEP_TIME_MS = 40;
	
	private IBurpExtenderCallbacks burpCallbacks;
	private PrintWriter stdout;
    private PrintWriter stderr;	
	
	public AntiCSRFToken(String tokenValue, String sessionID, IBurpExtenderCallbacks burpCallbacks)
	{
		this.tokenValue = tokenValue;
		this.sessionID = sessionID;
		this.burpCallbacks = burpCallbacks;
		
		// Initialize stdout and stderr
        stdout = new PrintWriter(burpCallbacks.getStdout(), true);
        stderr = new PrintWriter(burpCallbacks.getStderr(), true); 
		
	}
	
	public void ReleaseToken() 
	{
		stdout.println("Lock released for " + this.sessionID);
		this.isTokenBeingUsed = false;		
		
	}



	public void LockToken() throws InterruptedException 
	{
		int retries = 0;
		while(retries < AntiCSRFToken.MAX_LOCK_RETRIES)
		{
			if(!isTokenBeingUsed)
			{
				// Lock token
				this.isTokenBeingUsed = true;	
				return;
			}
			else
			{			
				Thread.sleep(AntiCSRFToken.SLEEP_TIME_MS);
				retries++;
			
			}
		}
		
		stdout.println("Mutex Lock timeout... Releasing Lock for " + this.sessionID);
		this.ReleaseToken();
		return;

		
	}

}
