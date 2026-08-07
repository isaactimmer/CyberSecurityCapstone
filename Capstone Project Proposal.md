**Project Scope: Deliverable (Explain)**   
Our group is looking to create a tool that helps security teams decide not ONLY what to fix but using the given time and resources they have, the order and vulnerabilities they should prioritize on fixing.. They would prioritize vulnerabilities that are more impactful towards them but vulnerabilities that seem the most dangerous on paper.   
Most vulnerability tools provide a static severity score meaning that once it is discovered, it is scored and rarely ever updated. The issue with this score is that it doesn't tell the company how likely someone is to exploit that vulnerability and whether attackers are going after it right now. As a result, issues that may be labeled "critical" may go untouched and unfixed for weeks, while issues labeled "medium" may be the ones that attackers go first. Furthermore, many tools have someone manually estimate how important a system is, which can be ranked too high or too low, which leads to a lot of subjectivity with vulnerabilities.   
The capacity-optimization planning tool is a tool that looks beyond scoring but builds a plan for remediation based on the team's time and resources. Using the team's capabilities (e.g. time and staff), the tool will determine which set of fixes, completed in which order, will provide the greatest risk reduction, rather than working with a vulnerability severity-ranked list. In order to make it tied with the business, the tool provides a map of how the company's systems connect with one another and highlights which systems are most valuable to protect, and treats anything that connects to those systems as more important, compared to a subjective guess led by one person. This can be changed and adjusted by the security lead, if in any case the map doesn't properly represent it. Businesses can give weight or adjust each factor differently since risks impact each company differently.   
We want to deliver a tool that will:   
\- Use real, present-time vulnerability data from public sources like known vulnerability records, exploitation likelihood, and confirmed active-attack alerts.  
\- A map of the company's systems and how they connect with one another, to determine the importance of each, rather than relying on subjectivity. (For mapping, we will be using a python script with NextBot API that will help sort out assets based on criticality, where it connects to, and distance from key asset. Using networkx, it will give us the distance from the key asset. We expect that a csv of all assets are given by a team such as the auditing team)  
\- Score each vulnerability using a specific formula that includes, not limited to, its severity, exploitation likelihood, whether it is being actively exploited, and how important the affected asset is..   
\- Take into account the security team's available resources (such as time), and produce a plan or structure of vulnerabilities to fix that provides the greatest risk-reduction.  
\- A side-by-side panel showcasing how it would look like if a team just worked based off a severity ranking, and report the percent improvement. This will show full openness and will allow the team to adjust their resources and see which choice is the better option.  
\- Automatic updates to a plan if a new vulnerability occurs or if something changes during the plan.

**Explain what you aim to achieve by creating this project/product**   
Every minute, the priority of a threat and vulnerability change, all threats and vulnerability do not remain the same or they do not apply in all cases. If the CVSS were to rank a threat or vulnerability as high for one group, it may not be as high for the other group. For this project, we aim to help security teams and companies decide what to fix first when they don't have time fix anything. Essentially, the question that we are helping them plan and answer, "Given the time and resources that we have, what are the risks, in what order, will give us the most risk reduction?" Most teams will look at a static vulnerability score and make the assumption that the score represents it for them. We are turning risk prioritization as part of the planning rather than making it a ranking issue. The tool uses actual vulnerability data and determines how important each affected system than relying on a guess.

**Who does it benefit? How does a business benefit? /Explain the business value of your idea**  
SOC: sees which vulnerabilities represent the most immediate real danger right now, not just the ones with the scariest severity label.  
Vulnerability Management: gets a specific, defensible order to work in, backed by real exploitation data, instead of a flat severity-sorted list.  
IT Operations/Infrastructure: gets a plan sized to the time they actually have available, instead of an unrealistic "fix everything labeled critical" backlog.  
Risk & Compliance: can point to exactly which unresolved risks matter most to the business at any given moment, and explain why in plain terms.  
Management/CISOs: get a way to justify where limited staff, time, and budget go, backed by a measurable result, and retain full authority to decide whether to follow the tool's recommendation or adjust it.

Companies and security teams will be able to create an actual actionable plan out of a bunch of data about information and vulnerability. We showcase a percentage of how much more risk a team eliminates by following our plan compared to a severity-first approach. 

**What is the industry gap that is being addressed?**  
Current prioritization framework produce a ranked list of what risks they should work on but the issue is that it doesn't help with what risks the company should prioritize. 45.4% of vulnerabilities that are discovered each year remain open and unresolved and this leads to organization's have a lot of logs of vulnerabilities that were not resolved that actually impacts them. Vulnerabilities and risks are not all the same for each company so creating a plan that is custom to each company will help them understand what to prioritize. 

**Initial Dataset and/or Technology Categories that you plan to use**  
National Vulnerability Database (CVE, CVSS Severity Scores), FIRST.org's Exploit Prediction Scoring (EPSS), CISA (KEV) catalog, CSV of assets, conditions, criticality, Python networkx library, Python pandas library, Greedy Heuristic

**Is there a pre-existing project that is similar to yours and what makes yours different**  
Tools exist that manage vulnerability or help identify vulnerabilities like a scanner. However, our product creates a plan based on the company and their assets, prioritizing the risks and vulnerabilities that are important for them.

**Do you foresee any risks or limitations that you will face while working on your project?**  
The current limitations that we may face is the timeline that we have of 2-3 weeks which forces us to limit our project instead of increasing the scope. The original project would've taken more time specifically in order to get more data. This leads to another limitation is our access to public data and what kind of data is available to the internet and for free.

