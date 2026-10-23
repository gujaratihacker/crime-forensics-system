from flask import Blueprint, render_template, Response
from utils.auth import get_db_connection
from services.awareness_service import ensure_awareness_scams_table

awareness_bp = Blueprint('awareness', __name__, url_prefix='/awareness')

@awareness_bp.route('/')
def index():
    """Renders the Cyber Safety and Awareness Hub."""
    scams = []
    conn = None
    try:
       conn = get_db_connection()
       ensure_awareness_scams_table(conn)
       with conn.cursor() as cursor:
          cursor.execute("""
             SELECT id, title, summary, warning_signs, safety_advice, icon
             FROM awareness_scams
             ORDER BY created_at DESC, id DESC
          """)
          scams = cursor.fetchall()
    except Exception as e:
       print(f"AWARENESS SCAM LOAD ERROR: {e}")
    finally:
       if conn:
          conn.close()
    return render_template('awareness/index.html', additional_scams=scams)

@awareness_bp.route('/download/<lang>')
def download_guide(lang):
    """Serves a generated text safety guide in English, Hindi, or Gujarati."""
    if lang == 'hi':
        content = """==================================================
साइबर सुरक्षा सुरक्षा गाइड और स्वच्छता चेकलिस्ट
==================================================

1. फ़िशिंग जागरूकता:
   - हमेशा प्रेषक का ईमेल पता या संदेश भेजने वाले का नंबर जांचें।
   - बैंक पासवर्ड, क्रेडिट कार्ड, या संवेदनशील जानकारी मांगने वाले किसी भी लिंक पर क्लिक करने से बचें।

2. यूपीआई सुरक्षा (UPI Safety):
   - पैसे प्राप्त करने के लिए आपको कभी भी अपना यूपीआई पिन (UPI PIN) दर्ज करने की आवश्यकता नहीं होती है।
   - केवल पैसे भेजने या खाता शेष जांचने के लिए ही पिन दर्ज करें।

3. बैंकिंग सुरक्षा (Banking Safety):
   - अपने नेटबैंकिंग खातों में टू-फैक्टर ऑथेंटिकेशन (2FA) सक्षम करें।
   - कभी भी अपना ओटीपी (OTP) या कार्ड का सीवीवी (CVV) नंबर किसी के साथ साझा न करें, चाहे वे बैंक अधिकारी होने का दावा ही क्यों न करें।

4. पासवर्ड सुरक्षा (Password Security):
   - हमेशा मजबूत और अद्वितीय पासवर्ड का उपयोग करें (जैसे: अक्षरों, संख्याओं और विशेष वर्णों का संयोजन)।
   - अलग-अलग खातों के लिए एक ही पासवर्ड का उपयोग करने से बचें।

5. सोशल मीडिया सुरक्षा (Social Media Safety):
   - अपनी गोपनीयता सेटिंग्स को केवल दोस्तों (Friends Only) तक सीमित करें।
   - व्यक्तिगत विवरण जैसे मोबाइल नंबर, वर्तमान स्थान या यात्रा योजनाओं को सार्वजनिक रूप से साझा न करें।

6. बच्चों की ऑनलाइन सुरक्षा (Child Online Safety):
   - बच्चों के उपकरणों पर माता-पिता के नियंत्रण (Parental Controls) और फिल्टर सक्षम करें।
   - उनके इंटरनेट और स्क्रीन समय की निगरानी करें और उन्हें साइबरबुलिंग के खिलाफ जागरूक करें।

7. वरिष्ठ नागरिकों की सुरक्षा (Senior Citizen Safety):
   - अनजान फोन कॉलों पर विश्वास न करें जो दावा करते हैं कि आपके खाते में कोई समस्या है या कोई लॉटरी जीती है।
   - कंप्यूटर/मोबाइल में किसी भी अनजान व्यक्ति के कहने पर 'AnyDesk' या 'TeamViewer' जैसे रिमोट एक्सेस ऐप इंस्टॉल न करें।

8. डीपफेक जागरूकता (Deepfake Awareness):
   - जब कोई संदिग्ध वीडियो या वॉयस नोट प्राप्त हो, तो चेहरे के हाव-भाव, आंखें झपकाने के तरीके और आवाज के लहजे को ध्यान से देखें।
   - सीधे दूसरे माध्यम से कॉल करके पुष्टि करें।

9. फर्जी नौकरी जागरूकता (Fake-Job Scams):
   - कोई भी असली कंपनी नौकरी देने के नाम पर अग्रिम पंजीकरण शुल्क, लैपटॉप शुल्क, या सुरक्षा जमा नहीं मांगती है।

10. निवेश घोटाला जागरूकता (Investment Scams):
    - केवल सेबी (SEBI) पंजीकृत ब्रोकरों और पोर्टल्स के माध्यम से ही निवेश करें।
    - व्हाट्सएप या टेलीग्राम समूहों पर दिए जाने वाले '100% दैनिक लाभ' वाले निवेश प्रस्तावों से दूर रहें।

==================================================
सुरक्षित रहें, सुरक्षित ऑनलाइन ब्राउज़ करें!
साइबर हेल्पलाइन नंबर: 1930
साइबर पोर्टल: cybercrime.gov.in
==================================================
"""
        filename = "cyber_safety_guide_hi.txt"
    elif lang == 'gu':
        content = """==================================================
સાયબર સુરક્ષા માર્ગદર્શિકા અને સ્વચ્છતા ચેકલિસ્ટ
==================================================

1. ફિશિંગ જાગૃતિ (Phishing Awareness):
   - હંમેશા મોકલનારનું ઇમેઇલ સરનામું અથવા મેસેજ મોકલનારનો નંબર તપાસો.
   - બેંક પાસવર્ડ, ક્રેડિટ કાર્ડ અથવા સંવેદનશીલ માહિતી માંગતી કોઈપણ લિંક પર ક્લિક કરવાનું ટાળો.

2. યુપીઆઈ સુરક્ષા (UPI Safety):
   - પૈસા મેળવવા માટે તમારે ક્યારેય પણ તમારો યુપીઆઈ પિન (UPI PIN) દાખલ કરવાની જરૂર હોતી નથી.
   - ફક્ત પૈસા મોકલવા અથવા એકાઉન્ટ બેલેન્સ ચેક કરવા માટે જ પિન દાખલ કરો.

3. બેંકિંગ સુરક્ષા (Banking Safety):
   - તમારા નેટબેન્કિંગ એકાઉન્ટ્સ પર ટુ-ફેક્ટર ઓથેન્ટિકેશન (2FA) સક્ષમ કરો.
   - કોઈપણ સંજોગોમાં તમારો ઓટીપી (OTP) અથવા કાર્ડનો સીવીવી (CVV) નંબર શેર કરશો નહીં, ભલે તેઓ બેંકના અધિકારી હોવાનો દાવો કરે.

4. પાસવર્ડ સુરક્ષા (Password Security):
   - હંમેશા મજબૂત અને અનન્ય પાસવર્ડનો ઉપયોગ કરો (જેમ કે: અક્ષરો, નંબરો અને વિશેષ ચિહ્નોનું સંયોજન).
   - વિવિધ એકાઉન્ટ્સ માટે એક જ પાસવર્ડનો ઉપયોગ કરવાનું ટાળો.

5. સોશિયલ મીડિયા સુરક્ષા (Social Media Safety):
   - તમારી ગોપનીયતા સેટિંગ્સને ફક્ત મિત્રો (Friends Only) સુધી મર્યાદિત કરો.
   - મોબાઈલ નંબર, વર્તમાન સ્થાન અથવા પ્રવાસની યોજનાઓ જેવી અંગત વિગતો જાહેરમાં શેર કરશો નહીં.

6. બાળકોની ઓનલાઇન સુરક્ષા (Child Online Safety):
   - બાળકોના ઉપકરણો પર પેરેંટલ કંટ્રોલ (Parental Controls) અને ફિલ્ટર્સ સક્ષम કરો.
   - તેમના ઇન્ટરનેટ વપરાશ અને સ્ક્રીન સમયનું નિરીક્ષણ કરો.

7. વરિષ્ઠ નાગરિક સુરક્ષા (Senior Citizen Safety):
   - અજાણ્યા ફોન કોલ્સ પર વિશ્વાસ ન કરો જે દાવો કરે છે કે તમારા ખાતામાં કોઈ સમસ્યા છે અથવા તમે લોટરી જીતી છે.
   - કોઈ અજાણ્યા વ્યક્તિના કહેવા પર કોમ્પ્યુટર/મોબાઈલમાં 'AnyDesk' અથવા 'TeamViewer' જેવી રીમોટ એક્સેસ એપ ઇન્સ્ટોલ ન કરો.

8. ડીપફેક જાગૃતિ (Deepfake Awareness):
   - શંકાસ્પદ વિડિઓ અથવા વૉઇસ નોટ મળે ત્યારે ચહેરાના હાવભાવ, આંખો પટપટાવવાની રીત અને અવાજના લયને ધ્યાનથી જુઓ.
   - બીજા માધ્યમથી ડાયરેક્ટ કૉલ કરીને ચકાસણી કરો.

9. નકલી નોકરી કૌભાંડો (Fake-Job Scams):
   - કોઈપણ અસલી કંપની નોકરી આપવાના નામે એડવાન્સ રજીસ્ટ્રેશન ફી અથવા સિક્યોરિટી ડિપોઝિટ માંગતી નથી.

10. રોકાણ કૌભાંડો (Investment Scams):
    - ફક્ત સેબી (SEBI) નોંધાયેલા બ્રોકર્સ અને પોર્ટલ દ્વારા જ રોકાણ કરો.
    - વોટ્સએપ કે ટેલિગ્રામ ગ્રુપ પર આપવામાં આવતી 'રોજ બમણું વળતર' આપતી સ્કીમોથી દૂર રહો.

==================================================
સુરક્ષિત રહો, સુરક્ષિત ઓનલાઇન બ્રાઉઝ કરો!
સાયબર હેલ્પલાઇન નંબર: 1930
સાયબર પોર્ટલ: cybercrime.gov.in
==================================================
"""
        filename = "cyber_safety_guide_gu.txt"
    else:
        content = """==================================================
CYBER SECURITY SAFETY GUIDE & HYGIENE CHECKLIST
==================================================

1. Phishing Awareness:
   - Always verify the sender's email address or message origin.
   - Avoid clicking on links demanding instant passwords, banking details, or urgent verification.

2. UPI Safety:
   - You NEVER need to enter your UPI PIN to receive money.
   - The PIN is only used for sending money or checking account balance.

3. Banking Safety:
   - Enable Two-Factor Authentication (2FA) on net banking accounts.
   - Never share OTP, CVV, or passwords with anyone, including individuals claiming to be bank managers.

4. Password Security:
   - Use long, complex passwords (combination of upper/lowercase letters, digits, and special characters).
   - Avoid using the same password across multiple online accounts.

5. Social Media Safety:
   - Lock your profiles and set post visibility to 'Friends Only'.
   - Avoid posting live location checks, contact numbers, or travel dates publicly.

6. Child Online Safety:
   - Enable strict parental controls, search filters, and kid-friendly configurations on family devices.
   - Educate kids about cyberbullying, online grooming, and the danger of sharing photos with strangers.

7. Senior Citizen Safety:
   - Beware of tech-support scams asserting your computer is infected, or callers claiming to be from insurance companies asking for urgent fees.
   - Never install remote access software (like AnyDesk or TeamViewer) under someone's telephonic instructions.

8. Deepfake Awareness:
   - Watch out for unnatural blinking, mismatched shadow borders, or sync issues between lips and audio in video clips.
   - Double-check requests for urgent funds by calling the sender on their primary phone number.

9. Fake-Job Scams:
   - Real employers will never ask you to pay for training materials, background check fees, or laptops.

10. Investment Scams:
    - Only invest via SEBI registered stockbrokers and certified investment portals.
    - Do not join Telegram or WhatsApp groups promising guaranteed high yields or inside trading tips.

==================================================
Stay Protected, Browse Safely!
National Cyber Helpline: 1930
National Cybercrime Portal: cybercrime.gov.in
==================================================
"""
        filename = "cyber_safety_guide_en.txt"
        
    return Response(
        content,
        mimetype="text/plain",
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )
