package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.Action;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

//import burp.*;

public class BurpExtender implements IHttpListener, ITab {
	
	 
	public IBurpExtenderCallbacks mycallbacks;
	public IExtensionHelpers myhelpers;
	private CSurferTokenJar latestAntiCSRFTokens;
	private CSurferJpanel panel;
	public static CSurferConfigurations CSurferConfigurator;
	
    private PrintWriter stdout;
    private PrintWriter stderr;	
	
    private boolean enabled;
		
	/*This method is invoked at startup. It is needed if you are implementing any method of IBurpExtenderCallbacks interface.
	In this example, we have implemented three such methods of this interface.*/
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
	{
		mycallbacks = callbacks;
		myhelpers = mycallbacks.getHelpers();
   	  	callbacks.setExtensionName("CSurfer");
   	  	BurpExtender.CSurferConfigurator = new CSurferConfigurations();
   	  	
   	  	callbacks.registerHttpListener(this);
   	  	this.latestAntiCSRFTokens = new CSurferTokenJar(callbacks);
   	  	
        // Initialize stdout and stderr
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true); 
        
        enabled = true;
   	 
   	  	// create the UI in a separate thread
		SwingUtilities.invokeLater(new Runnable() 
		{					  
			@Override
		      public void run()
		      {
					panel = new CSurferJpanel();
					panel.Init();
					BurpExtender.CSurferConfigurator = panel.GetConfigurations();
					
					//Add save handler to update configurations
					panel.saveButton.addActionListener(new ActionListener() {											

						@Override
						public void actionPerformed(ActionEvent arg0) {
//							BurpExtender.CSurferConfigurator.Update(panel.getConfigurations());
							BurpExtender.CSurferConfigurator = panel.GetConfigurations();
							
						}
					});
					
					//Add enable/disable handler
					panel.enableDisableButton.addActionListener(new ActionListener() {											

						@Override
						public void actionPerformed(ActionEvent arg0) {
							if(enabled) {
								panel.enableDisableButton.setText("Enable");
								enabled = false;
								stdout.println("*** CSurfer disabled ***");
							} else {
								panel.enableDisableButton.setText("Disable");
								enabled = true;
								stdout.println("*** CSurfer enabled ***");
							}
							
						}
					});
					
					//Add export configurations handler
					panel.exportConfigButton.addActionListener(new ActionListener() {											

						@Override
						public void actionPerformed(ActionEvent arg0) {

							exportConfigurations();
							
						}
					});
					
					//Add load configurations handler
					panel.loadConfigButton.addActionListener(new ActionListener() {											

						@Override
						public void actionPerformed(ActionEvent arg0) {
							
							loadConfigurations();
							
						}
					});
					
					callbacks.customizeUiComponent(panel);		          		          		        
					callbacks.addSuiteTab(BurpExtender.this);
										
		      }
		  });
		
	}



	@Override
	public void processHttpMessage(int toolFlag, boolean isRequest, IHttpRequestResponse messageInfo)			
	{		
		
		if(enabled) {
		
			IRequestInfo request = myhelpers.analyzeRequest(messageInfo.getRequest());
			String currentSessionID = this.ExtractSessionID(request);		
			
	//		stdout.println("Parameter value: " + BurpExtender.CSurferConfigurator.parameter1);
			
			if(isRequest)
			{				
				this.UpdateAntiCSRFToken(request, messageInfo, currentSessionID);							
			}
			else //Response
			{
				IResponseInfo response = myhelpers.analyzeResponse(messageInfo.getResponse());
				this.UpdateAntiCSRFToken(response, messageInfo, currentSessionID);									
			}
			
		}
	
	}
	
	private void exportConfigurations() {
				
		JFrame parentFrame = new JFrame();
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setDialogTitle("Configuration output file");
		
		int userSelection = fileChooser.showSaveDialog(parentFrame);
		
		if(userSelection == JFileChooser.APPROVE_OPTION) {
						
			File outputFile = fileChooser.getSelectedFile();
			FileWriter fw;
			try {
				fw = new FileWriter(outputFile);
				
				fw.write("" + BurpExtender.CSurferConfigurator.MAX_NUM_SESSIONS + "\n");
				fw.write(BurpExtender.CSurferConfigurator.ANTI_CSRF_TOKEN_NAME + "\n");
				fw.write(BurpExtender.CSurferConfigurator.SESSION_ID_NAME + "\n");
				fw.write(BurpExtender.CSurferConfigurator.ANTI_CSRF_RESPONSE_REGEX + "\n");
				fw.write("" + BurpExtender.CSurferConfigurator.ANTI_CSRF_RESPONSE_REGEX_MATCH_GROUP + "\n");
							 
				fw.close();
			} catch (IOException e) {
				stderr.println("ERROR");
				stderr.println(e.toString());
				return;
			}			
				
		}
		
	}
	
	private void loadConfigurations() {
		
		JFrame parentFrame = new JFrame();
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setDialogTitle("Configuration input file");
		
		int userSelection = fileChooser.showSaveDialog(parentFrame);
		
		if(userSelection == JFileChooser.APPROVE_OPTION) {
			
			File inputFile = fileChooser.getSelectedFile();
						
			try {
				
				BufferedReader br = new BufferedReader(new FileReader(inputFile));
				 				
				BurpExtender.CSurferConfigurator.MAX_NUM_SESSIONS = Integer.parseInt(br.readLine());
				panel.maxSessionsTextField.setText("" + BurpExtender.CSurferConfigurator.MAX_NUM_SESSIONS);
				BurpExtender.CSurferConfigurator.ANTI_CSRF_TOKEN_NAME = br.readLine();
				panel.tokenNameTextField.setText(BurpExtender.CSurferConfigurator.ANTI_CSRF_TOKEN_NAME);
				BurpExtender.CSurferConfigurator.SESSION_ID_NAME = br.readLine();
				panel.sessionIDTextField.setText(BurpExtender.CSurferConfigurator.SESSION_ID_NAME);
				BurpExtender.CSurferConfigurator.ANTI_CSRF_RESPONSE_REGEX = br.readLine();
				panel.tokenResponseRegexTextField.setText(BurpExtender.CSurferConfigurator.ANTI_CSRF_RESPONSE_REGEX);
				BurpExtender.CSurferConfigurator.ANTI_CSRF_RESPONSE_REGEX_MATCH_GROUP = Integer.parseInt(br.readLine());
				panel.tokenMatchGroupTextField.setText("" + BurpExtender.CSurferConfigurator.ANTI_CSRF_RESPONSE_REGEX_MATCH_GROUP);
			 				
				br.close();
				
			} catch (Exception e) {
				stderr.println("ERROR");
				stderr.println(e.toString());
				return;
			}
			
			
		}
	}
	

	private String ExtractSessionID(IRequestInfo request) 
	{
		List<IParameter> parameters = request.getParameters();		
		for (IParameter parameter : parameters) 
		{
			if(parameter.getName().equals(BurpExtender.CSurferConfigurator.SESSION_ID_NAME) && parameter.getType() == IParameter.PARAM_COOKIE)
			{
				return parameter.getValue();
			}
		}		
		return null;
	}



	private void UpdateAntiCSRFToken(IResponseInfo response, IHttpRequestResponse messageInfo, String sessionID)  
	{		
		int bodyOffset = response.getBodyOffset();
		byte[] bodyBytes = Arrays.copyOfRange(messageInfo.getResponse(), bodyOffset, messageInfo.getResponse().length);
		String body = myhelpers.bytesToString(bodyBytes);
		Pattern tokenPattern = Pattern.compile(BurpExtender.CSurferConfigurator.ANTI_CSRF_RESPONSE_REGEX);
		Matcher matcher = tokenPattern.matcher(body);		
		if (matcher.find()) 
		{
			String newTokenValue = matcher.group(BurpExtender.CSurferConfigurator.ANTI_CSRF_RESPONSE_REGEX_MATCH_GROUP);
			
			
			
			//Handle the case if there's a new cookie sent in the response, so the session ID is going to be the new one, not the old
			String newSessionID = this.GetNewSessionID(response);
			
			if(newSessionID != null)
				sessionID = newSessionID;
			
			AntiCSRFTokenStatus status = this.latestAntiCSRFTokens.AddToken(newTokenValue, sessionID);
			
			switch(status)
			{		
			case TOKEN_ADDED:
				stdout.println("Token found in response: " + newTokenValue + ". Added for session ID " + sessionID);
				
				break;
			case TOKEN_UPDATED:
				stdout.println("Token found in response: " + newTokenValue + ". Updated for session ID " + sessionID);			
				break;
			default:
				throw new UnknownError();			
			}
			
			status = this.latestAntiCSRFTokens.GarbageCollect();
			
			switch (status) {
			case TOKENS_GARBAGE_COLLECTED:
				stdout.println("Tokens garbage collector: succefully cleaned.");
				break;

			case TOKENS_LESS_THAN_MAX:
				stdout.println("Tokens garbage collector: tokens less than max.");
				break;
				
			default:
				throw new UnknownError();	
			}
			
			
		}
		
	}



	private String GetNewSessionID(IResponseInfo response) 
	{
		List<ICookie> cookies = response.getCookies();		
		for (ICookie cookie : cookies) 
		{
			if(cookie.getName().equals(BurpExtender.CSurferConfigurator.SESSION_ID_NAME))
			{
				return cookie.getValue();
			}
		}
		return null;
	}



	private void UpdateAntiCSRFToken(IRequestInfo request, IHttpRequestResponse messageInfo, String sessionID) 
	{				
		List<IParameter> parameters = request.getParameters();
		
		for (IParameter parameter : parameters) 
		{
			if(parameter.getName().equals(BurpExtender.CSurferConfigurator.ANTI_CSRF_TOKEN_NAME))
			{
				String currentTokenValue = this.latestAntiCSRFTokens.GetToken(sessionID);
												
				//If Anti-CSRF token is incorrect and we have a newer value, then correct it
				if(currentTokenValue != null && !parameter.getValue().equals(currentTokenValue))
				{
					IParameter newParameter = myhelpers.buildParameter(
							parameter.getName(), currentTokenValue, parameter.getType());
					
					messageInfo.setRequest(myhelpers.updateParameter(
						messageInfo.getRequest(), newParameter));
					stdout.println("Token updated in reqeust: " + currentTokenValue + " for session ID: " + sessionID);
				}

				//Stop inspecting further parameters
				break;			
			}			
		}
	}



	@Override
	public String getTabCaption() 
	{
		return "CSurfer";
	}



	@Override
	public Component getUiComponent() 
	{
		return this.panel;
	}


}
