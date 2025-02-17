using System.Net;
using System.Net.Mail;
using AuthenticationCenter.Configuration;
using Microsoft.Extensions.Options;

namespace AuthenticationCenter.Services;

public class EmailService
{
    private readonly SmtpSetting _smtpSettings;

    public EmailService(IOptions<SmtpSetting> smtpSettings)
    {
        _smtpSettings = smtpSettings.Value;
    }
    
    public async Task SendEmail(string email, string subject, string htmlMessage)
    {
        try
        {
            using (var message = new MailMessage())
            {
                message.From = new MailAddress(_smtpSettings.SenderEmail, _smtpSettings.SenderName);
                message.To.Add(new MailAddress(email));
                message.Subject = subject;
                message.Body = htmlMessage; 
                message.IsBodyHtml = true;
                
                using (var smtpClient = new SmtpClient(_smtpSettings.Server, _smtpSettings.Port))
                {
                    smtpClient.Credentials = new NetworkCredential(_smtpSettings.UserName, _smtpSettings.Password);
                    smtpClient.EnableSsl = true;
                    
                    await smtpClient.SendMailAsync(message);
                }
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Error sending email.", ex);
        }
    }
    
}