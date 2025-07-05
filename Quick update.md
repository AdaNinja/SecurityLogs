## Architecture
scenarios/macro_attack/
├── macro_simulation_simple.py      # Basic attack variant
├── macro_simulation_medium.py      # Intermediate attack variant  
├── macro_simulation_complex.py     # Advanced attack variant
├── logging_utils.py                # Traditional logging system
├── analysis_tool.py               # Automated analysis engine
├── visualization_tool.py          # Results visualization
├── scenario.yaml                  # Configuration definitions
└── output/                        # Generated attack artifacts
    ├── simple/                    # 11 files, 7.7KB
    ├── medium/                    # 20 files, 16.7KB
    └── complex/                   # 69 files, 64.3KB


### Key Features
**Real Activity Execution**: Creates actual files, executes commands, performs network activities
**Traditional Logging**: Generates system logs, network logs, file operation logs, process logs
**Automated Analysis:** Detects obfuscation, encryption, network activity, persistence mechanisms
**Multi-Dimensional Complexity Model**
The framework implements a weighted complexity scoring system with four key dimensions:
Background Activity Weight (0.2-0.5): Simulates normal user behavior
Attack Stealth Weight (0.15-0.5): Determines detection difficulty
Evasion Technique Weight (0.05-0.3): Anti-detection mechanisms
Noise Level Weight (0.0-0.3): Environmental interference


### Model and academic support
Georgiadou 等人在“Assessing MITRE ATT&CK Risk Using a Cyber-Security Culture Framework”中，通过融合 MITRE ATT&CK 中的 TTP（战术、技术、程序）与组织安全文化指标，揭示了隐蔽（stealth）和规避（evasion）技术在实战攻击中的核心地位：这些技术往往是红队/APT 在后阶段维持持久性并逃避检测的关键手段。基于这一发现，我们在中高级复杂度预设中相应提高了隐蔽性和规避技术的权重，保证模型对高阶攻击手法的敏感度。
#### Model
Complexity Score = 
  (Background Score × w₁) + (Stealth Score × w₂) + 
  (Evasion Score × w₃) + (Noise Score × w₄)
- **Background Score**: 活动数量×0.5
- **Stealth Score**: 隐蔽级别（low/med/high）映射为1/2/3
- **Evasion Score**: 规避手段数×1
- **Noise Score**: (活动数×平均强度)/2.0

	  Basic  Intermediate  Advanced
- w1= 0.35       0.30                 0.25
- w2=0.25        0.35                 0.40
- w3=0.25         0.25-0.30          0.30
- w4=0.15        0.10                    0.05


### Result
Variant,Total_Files,Total_Size,Total_Lines,Obfuscation_Files,Encryption_Files,Network_Files,Command_Files,Persistence_Files,Stealth_Level,Complexity_Level,Evasion_Techniques

simple,11,7767,69,0,3,2,3,5,Low,Medium,8

medium,20,16700,144,3,4,6,6,5,Medium,Medium,12

complex,69,64289,583,9,25,24,15,12,Medium,High,46

#### Update
- Adjust max score threshold: <=3.0 for basic, <=6.0 for intermediate, <=25.0 for advanced 

### Key Achievements
**Validated Complexity Model:** Successfully demonstrated that different configurations produce measurably different attack characteristics
Automated Analysis: Built tools that can automatically detect and quantify attack complexity
**Traditional Logging**: Implemented realistic logging that mirrors real-world security monitoring
**Scalable Framework:** Created a reusable system for testing different attack scenarios



Next Steps
1. deploy to windows11 and linux
2. read more paper to refine attack chain design
## References
1. @inproceedings{10.1145/3538969.3544420,
author = {Ahmed, Mohamed and Panda, Sakshyam and Xenakis, Christos and Panaousis, Emmanouil},
title = {MITRE ATT&CK-driven Cyber Risk Assessment},
year = {2022},
isbn = {9781450396707},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3538969.3544420},
doi = {10.1145/3538969.3544420},
articleno = {107},
numpages = {10},
keywords = {Attack graph, Cyber risk assessment, MITRE ATT&CK, Threat modelling.},
location = {Vienna, Austria},
series = {ARES '22}
}
2. arXiv:2403.17458v3 [cs.CR] 28 Mar 2024 Expectations Versus Reality: Evaluating Intrusion Detection Systems in Practice
3. @inproceedings{Sharafaldin2018TowardGA, title={Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization}, author={Iman Sharafaldin and Arash Habibi Lashkari and Ali A. Ghorbani}, booktitle={International Conference on Information Systems Security and Privacy}, year={2018}, url={https://api.semanticscholar.org/CorpusID:4707749} }
4. @inproceedings{Ullah2020ASF, title={A Scheme for Generating a Dataset for Anomalous Activity Detection in IoT Networks}, author={Imtiaz Ullah and Qusay H. Mahmoud}, booktitle={Canadian Conference on AI}, year={2020}, url={https://api.semanticscholar.org/CorpusID:218539986} }
5. @article{Patel2023Odids2022GA, title={Od-ids2022: generating a new offensive defensive intrusion detection dataset for machine learning-based attack classification}, author={N. D. Patel and B. M. Mehtre and Rajeev Wankar}, journal={International Journal of Information Technology}, year={2023}, volume={15}, pages={4349-4363}, url={https://api.semanticscholar.org/CorpusID:261926961} }





