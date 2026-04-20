**ENSURE TO GO THROUGH THIS FILE BEFORE ACCESSING THE PROJECT**

This is my final year Individual project.
For the functioning of this project, the following API keys are required that the user has to generate.
-->GROQ API KEY: Can be generated via https://console.groq.com/keys
-->NVD API KEY: Can be generated upon registration via https://nvd.nist.gov/developers/request-an-api-key .

Once you have you api keys generated, navigate to ** pages/platform.py ** code and replace the placeholder at line 17 with the GROQ API KEY and the placeholder at line 16 with the NVD API KEY
Also navigate to ** rss2.py ** and replace the placeholder at line 725 with the NVD API KEY.

Since this is a threat intelligence platform, the threats are first parsed from the rss feeds and then displayed on the dashboard.The code is built upon streamlit.

Follow the beow steps to access the dashboard.
--Open the folder via Vs Code terminal
--So firstly please run the ** rss2.py ** code to get the latest threat advisories from the sources. 
--Then run the ** auth.py ** code.this is the authentication page befor the main dashboard by typing:
      -streamlit run auth.py---->you will redirected to the login/signup page.Ensure to signup
      -once you signup it will automatically take to to the main dashboard(platform.py)

The other files in the repository support all the database and chatbot functionalities of the project.
