"""Shared regexes for the content and tool layers. English + French + some Spanish.

Precision first: every pattern must describe an instruction aimed at an agent or an explicit change of the
payment rules, never ordinary business vocabulary (ERP system, rate limit, shipping fee, you must be 18...).
Whitespace is always \\s+ so doubled spaces or line breaks do not break a match.
"""
from __future__ import annotations

import os
import re

I = re.I
IM = re.I | re.M

OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+|your\s+|these\s+|my\s+)?(?:previous\s+|prior\s+|above\s+|earlier\s+|preceding\s+|existing\s+|original\s+|system\s+)?"
    r"(?:instructions?|rules?|prompts?|guidelines?|constraints?|mandate|safety\s+(?:rules?|checks?)|guardrails?)\b"
    r"|\bnew\s+(?:system\s+)?instructions?\s*:|\bfollow\s+(?:these|the\s+following|my)\s+(?:new\s+)?instructions\b"
    r"|\bdeveloper\s+mode\b|\bjailbreak|\bdo\s+anything\s+now\b|\bact\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|evil|dan)\b"
    r"|\byou\s+are\s+now\s+(?:an?\s+|the\s+)?(?:\w+\s+){0,2}(?:agent|assistant|bot|ai|model|mode|system)\b|\byou\s+are\s+now\s+(?:free|unrestricted|allowed|authorized|permitted)\b"
    r"|\bfrom\s+now\s+on,?\s+(?:you|ignore|always|never|do\s+not)\b"
    r"|(?:^|[\n\[<|>])\s*system\s*:\s"
    r"|\bignor(?:e|ez)\s+(?:les|tes|vos|toutes\s+les|mes)\s+(?:instructions?|consignes|r[èe]gles|limites?|garde-fous)\b"
    r"|\boublie(?:z)?\s+(?:tes|vos|les|toutes\s+les)\s+(?:instructions?|consignes|r[èe]gles)\b|\bnouvelles?\s+(?:instructions?|consignes)\s*:"
    r"|\bignora\s+(?:todas\s+)?(?:las\s+)?instrucciones\b|\bolvida\s+(?:tus|las)\s+(?:instrucciones|reglas)\b",
    IM,
)

CHAT_DELIMITERS = re.compile(
    r"<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|\[/?INST\]|<<SYS>>|</?system>|</?assistant>|</?user>"
    r"|(?:^|\s)#{2,}\s*(?:system|assistant)\b|^\s*(?:Human|Assistant|System)\s*:\s",
    IM,
)

# a direct address to the agent: "AI agent:", "Agents,", "note to the automation", "if you are an AI", "as an AI"
AGENT_VOCATIVE = re.compile(
    r"(?:^|[\s>\"'(\[{*_-])(?:ai|a\.i\.|agents?|assistants?|llms?|bots?|automations?|claude|gpt|copilot|chatbots?|ia)"
    r"(?:\s+(?:agents?|assistants?|systems?|models?|readers?|automations?|clients?|shoppers?|payers?))?\s*[:,!]\s"
    r"|\b(?:note|message|notice|hint|memo|instructions?|attention|reminder)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?(?:\w+\s+){0,2}(?:ais?|agents?|assistants?|automations?|bots?|models?|llms?)\b"
    r"|\bif\s+you\s+are\s+(?:an?\s+)?(?:ai|agent|assistant|llm|bot|automated|autonomous|language\s+model)\b"
    r"|\bas\s+an?\s+(?:ai|agent|assistant|llm|language\s+model|automated\s+\w+)\b"
    r"|\b(?:dear|hello|hi|hey)\s+(?:ai|agent|assistant|bot|automation)\b"
    r"|\b(?:for|to)\s+(?:ai|automated|autonomous|llm)\s+(?:agents?|assistants?|clients?|readers?|systems?|shoppers?)\s*[:,]"
    r"|\b(?:ai|agent|assistant)[- ](?:only|readable|instructions?|hint|directive)s?\b"
    r"|\b(?:agent|assistant|ia)\s*:\s|\bsi\s+tu\s+es\s+un(?:e)?\s+(?:ia|agent|assistant)\b|\bpour\s+les\s+agents\s+(?:ia\s+)?[:,]"
    r"|\bsi\s+eres\s+un(?:a)?\s+(?:ia|agente|asistente)\b",
    IM,
)

IMPERATIVE_PAY = re.compile(
    r"\b(?:approve|re-?approve|re-?authori[sz]e|transfer|send|pay|wire|remit|execute|authori[sz]e|release|forward|withdraw|swap|bridge|move)\b(?!\s+(?:your\s+)?(?:api\s+key|request|header))"
    r"|\bsign\b(?!\s*[-]?\s*(?:in|up|on|out)\b)"
    r"|\bset\s+(?:the\s+)?(?:recipient|payee|beneficiary|destination|amount)\b|\bchange\s+(?:the\s+)?(?:recipient|address|treasury|beneficiary|payee|destination)\b"
    r"|\buse\s+(?:the\s+)?(?:new|this|following)\s+(?:address|wallet|treasury|account|recipient)\b|\bredirect\s+(?:the\s+)?(?:payment|funds|payout)\b"
    r"|\b(?:approuve|r[ée]-?approuve|transf[èe]re|envoie|envoyez|paie|payez|vire|virez|signe|ex[ée]cute|autorise|d[ée]bloque)\b"
    r"|\b(?:aprueba|transfiere|env[ií]a|paga|firma|autoriza)\b",
    I,
)

# instructions that bend the agent's process (skip review, hide from the user, act before paying)
IMPERATIVE_CONTROL = re.compile(
    r"\byou\s+(?:must|should|need\s+to|have\s+to|are\s+required\s+to)\s+(?:now\s+|immediately\s+|also\s+|first\s+|always\s+)?"
    r"(?:approve|re-?approve|transfer|send|pay|wire|ignore|disregard|skip|bypass|use|set|change|execute|sign\b(?!\s*[-]?\s*(?:in|up))|forward|authori[sz]e|redirect|not\s+ask|not\s+tell|not\s+notify|never\s+ask)\b"
    r"|\bskip\s+(?:the\s+|any\s+|all\s+)?(?:human\s+|manual\s+)?(?:review|confirmation|verification|approval|guard|checks?|validation)s?\b"
    r"|\bdo\s+not\s+(?:ask|tell|notify|inform|consult|alert|warn)\s+(?:the\s+)?(?:user|human|owner|operator|customer|principal)\b"
    r"|\bwithout\s+(?:asking|notifying|informing|alerting|consulting)\s+(?:the\s+)?(?:user|human|owner|operator)\b"
    r"|\bai[- ]friendly\s+(?:captcha|checkout|endpoint|path|flow)\b|\bsolve\s+this\s+captcha\s+by\b"
    r"|\bbefore\s+(?:any|each|every)\s+(?:payment|transfer|payout)\s*,?\s+(?:set|change|use|send|redirect|forward|approve|replace)\b"
    r"|\b(?:proceed|continue|execute|do\s+this|complete\s+this)\s+(?:silently|quietly|without\s+(?:confirmation|asking|review))\b"
    r"|\bne\s+(?:demande|pr[ée]viens|informe|dis)\s+(?:rien\s+)?(?:pas\s+)?(?:à\s+)?(?:l'|le\s+|la\s+|au\s+)?(?:utilisateur|humain|client|propri[ée]taire)\b"
    r"|\bsans\s+(?:demander|pr[ée]venir|confirmation|validation)\s+(?:humaine|à\s+l'utilisateur|du\s+client)?\b|\btu\s+dois\s+(?:maintenant\s+)?(?:approuver|payer|transf[ée]rer|ignorer|virer)\b"
    r"|\bno\s+(?:le\s+)?(?:preguntes|avises|digas)\s+al\s+(?:usuario|humano)\b|\bsin\s+(?:preguntar|confirmar)\b",
    I,
)

# explicit change of the payment rules: hard
MANDATE_OVERRIDE = re.compile(
    r"\b(?:new|updated|increased|raised|revised|temporary)\s+(?:spending\s+|daily\s+|per[- ]order\s+|payment\s+|transfer\s+|approval\s+|transaction\s+)?(?:limit|cap|threshold|ceiling|allowance)\s+(?:is|of|:|=|set|now)\b"
    r"|\b(?:spending|payment|transfer|daily|per[- ]order|previous|old|prior|current|usdc|\d[\d,.]*\s*\w*)\s+limit\s+(?:is\s+|are\s+|has\s+been\s+|have\s+been\s+|was\s+)?(?:deprecated|obsolete|removed|lifted|suspended|disabled|raised|increased|waived|no\s+longer\s+(?:applies|valid|enforced|in\s+effect))\b"
    r"|\b(?:ignore|disregard|skip|bypass|waive)\s+(?:the\s+|your\s+|any\s+|all\s+)?(?:previous\s+|prior\s+|old\s+|usual\s+|normal\s+)?(?:\d[\d,.]*\s*\w*\s+)?(?:limits?|caps?|thresholds?|allowance)\b"
    r"|\bno\s+(?:longer\s+any\s+|more\s+)?(?:spending|payment|transfer|amount|approval|per[- ]order|transaction)\s+limits?\b"
    r"|\b(?:approval|allowance|authori[sz]ation)\s+(?:is\s+|has\s+been\s+|was\s+)?(?:deprecated|obsolete|outdated|expired|invalid|revoked)\b"
    r"|\bre-?approve\b|\bre-?authori[sz]e\s+(?:the\s+)?(?:payment|transfer|allowance|spend)"
    r"|\bmigrat(?:e|ed|ion)\s+(?:of\s+|to\s+)?(?:the\s+|a\s+|your\s+)?(?:new\s+)?(?:approval|allowance)\b|\b(?:allowance|approval)\s+migration\b"
    r"|\bupdate\s+(?:your\s+)?(?:allowance|approval|spending\s+limit)\s+to\b"
    r"|\bnouveau\s+plafond\b|\bplafond\s+(?:supprim|lev|augment|relev)|\bnouvelle\s+limite\s+(?:de\s+)?(?:d[ée]pense|paiement|virement)\b|\b(?:tr[ée]sorerie|coffre)\s+(?:a\s+)?(?:migr|d[ée]m[ée]nag|chang)"
    r"|\br[ée]-?approuve|\bignor(?:e|ez)\s+(?:la|le|votre|ton)\s+(?:limite|plafond)\b"
    r"|\bnuevo\s+l[ií]mite\s+de\s+(?:gasto|pago)\b|\bignora\s+el\s+l[ií]mite\b",
    I,
)

# vendor announces new bank details: legitimate sometimes, the classic mandate fraud otherwise -> human call-back
BANK_DETAIL_CHANGE = re.compile(
    r"\bnew\s+(?:bank|payment|settlement|payout|remittance|beneficiary)\s+(?:account|address|details|wallet|iban|information)\b|\bnew\s+iban\b"
    r"|\b(?:bank|payment|remittance|beneficiary|account)\s+(?:account\s+|details\s+|information\s+)?(?:have|has)\s+(?:recently\s+)?changed\b"
    r"|\b(?:please\s+)?(?:update|change|replace)\s+(?:our\s+|the\s+|your\s+)?(?:bank|payment|remittance|beneficiary)\s+(?:details|account|address|information|records)\b"
    r"|\b(?:send|route|make|direct)\s+(?:all\s+)?(?:future\s+|further\s+|the\s+)?payments?\s+to\s+(?:the\s+)?(?:new|following|this)\b|\bupdated\s+(?:bank|payment|remittance)\s+(?:details|information)\b"
    r"|\bnouveau\s+(?:rib|iban|compte\s+bancaire)\b|\bnouvelles\s+coordonn[ée]es\s+bancaires\b|\bnouvelle\s+adresse\s+de\s+(?:paiement|r[èe]glement|facturation\s+et\s+paiement)\b|\bchangement\s+(?:de\s+)?(?:rib|iban|coordonn[ée]es\s+bancaires)\b"
    r"|\b(?:treasury|vault|payout\s+wallet|settlement\s+(?:address|wallet)|our\s+wallet)\s+(?:has\s+|have\s+|was\s+)?(?:migrated|moved|changed|been\s+(?:relocated|updated|migrated))\b"
    r"|\bmigrat(?:e|ed|ion)\s+(?:of\s+|to\s+)?(?:the\s+|a\s+|your\s+)?(?:new\s+)?(?:treasury|vault|wallet|funds|payout|settlement)\b|\b(?:treasury|funds?|wallet)\s+migration\b"
    r"|\bnueva\s+cuenta\s+bancaria\b|\bnuevo\s+iban\b",
    I,
)

URGENCY = re.compile(
    r"\burgent(?:ly)?\b|\bimmediately\b|\bright\s+now\b|\bwithin\s+(?:the\s+next\s+)?\d+\s?(?:min|minutes?|hours?|h)\b|\bbefore\s+\d{1,2}\s?(?:am|pm|h)\b"
    r"|\bfinal\s+(?:notice|warning|reminder)\b|\blast\s+chance\b|\bact\s+now\b|\bexpires?\s+(?:today|soon|in\s+\d)\b|\btime[- ]sensitive\b"
    r"|\bfunds?\s+(?:are\s+|is\s+)?at\s+risk\b|\bto\s+(?:secure|protect|avoid\s+losing)\s+(?:your\s+)?funds\b|\baccount\s+(?:will\s+be\s+)?(?:suspended|locked|closed|terminated)\b"
    r"|\bconfidential\b|\bdo\s+not\s+(?:tell|inform|notify|share)\b|\bkeep\s+(?:this\s+)?(?:private|secret|between\s+us)\b|\bdiscreet(?:ly)?\b|\btell\s+no\s+one\b"
    r"|\bimm[ée]diatement\b|\bderni(?:er|[èe]re)\s+(?:avertissement|rappel|chance)\b|\bconfidentiel(?:le)?\b|\bne\s+(?:le\s+)?dites\s+(?:à\s+personne|rien)\b|\bsous\s+\d+\s?(?:min|minutes|heures?)\b|\bsans\s+d[ée]lai\b"
    r"|\burgente\b|\binmediatamente\b|\bconfidencial\b",
    I,
)
# standard email footers and legal notices are not pressure
DISCLAIMER = re.compile(
    r"(?:this\s+(?:e-?mail|message|communication)|the\s+information\s+(?:contained|in\s+this)|its?\s+contents?)[^.\n]{0,80}confidential"
    r"|confidentiality\s+notice|intended\s+(?:solely\s+|only\s+)?for\s+the\s+(?:addressee|recipient|named)|if\s+you\s+(?:have\s+)?received\s+(?:this|it)\s+in\s+error"
    r"|ce\s+(?:message|courriel|mail)[^.\n]{0,60}confidentiel|destin[ée]\s+(?:uniquement\s+)?au\s+destinataire",
    I,
)

APPROVAL_CLAIM = re.compile(
    r"\b(?:already|pre)[- ]?(?:approved|authori[sz]ed|validated|verified|cleared|confirmed|signed\s+off)\s+(?:by|for\s+(?:ai|automated|api)\s+agents?)\b"
    r"|\b(?:compliance|finance|the\s+ceo|the\s+cfo|management|legal|the\s+owner|the\s+user|the\s+human|the\s+principal|your\s+operator)\s+(?:has\s+|have\s+)?(?:already\s+)?(?:approved|authori[sz]ed|validated|signed\s+off|confirmed|cleared)\s+(?:this|it|the)\b"
    r"|\bno\s+(?:further\s+|human\s+|additional\s+|manual\s+)?(?:confirmation|approval|review|verification|validation)\s+(?:is\s+)?(?:needed|required|necessary)\b"
    r"|\bpre-?authori[sz]ed\s+for\s+(?:automated|ai|api)\s+(?:clients?|agents?|use)\b"
    r"|\bd[ée]j[àa]\s+(?:approuv|valid|autoris)[ée]e?\s+par\b|\bpas\s+besoin\s+de\s+(?:confirmation|validation)\b|\baucune\s+(?:confirmation|validation)\s+(?:n'est\s+)?(?:n[ée]cessaire|requise)\b",
    I,
)
DISABLE_CONTROLS = re.compile(
    r"\b(?:disable|turn\s+off|bypass|suppress|silence|stop|deactivate|switch\s+off)\s+(?:all\s+|the\s+|any\s+|your\s+)?(?:confirmations?|confirmation\s+step|logging|logs|audit(?:ing)?|audit\s+trail|alerts|safety\s+checks?|the\s+guard|verification\s+step|human\s+review)\b"
    r"|\bd[ée]sactive(?:z)?\s+(?:les\s+|la\s+|le\s+|l')?(?:confirmations?|logs|journaux|audit|v[ée]rification|garde)\b",
    I,
)

AGENT_TARGETED = re.compile(
    r"\bofficial\s+(?:store|site|shop|vendor|partner|endpoint|service|provider)\s+for\s+(?:ai\s+)?(?:agents?|assistants?|bots|automated\s+\w+)\b"
    r"|\b(?:ai|agent|llm|bot)[- ](?:verified|approved|trusted|recommended|optimi[sz]ed|preferred|certified)\b(?!\s+recommendations)"
    r"|\b(?:agents?|ais?|assistants?|bots?)[, ]+(?:please\s+)?(?:use|choose|select|prefer|trust|pick)\s+(?:this|our|the\s+following)\b"
    r"|\brecommended\s+for\s+(?:ai\s+)?(?:agents|assistants|bots|automated\s+(?:clients|buyers))\b|\b(?:cheapest|best|official|verified)[^.\n]{0,40}\bfor\s+(?:ai|automated|autonomous)\s+(?:agents|clients|buyers)\b"
    r"|\bboutique\s+officielle\s+pour\s+(?:les\s+)?agents\b",
    I,
)

FOLLOWUP_FEE = re.compile(
    r"\b(?:customs?|import|release|clearance|unlock|redelivery|re-delivery|re-?activation|verification)\s+(?:fee|charge|payment|tax|deposit)\b"
    r"|\brefund\s+link\b|\bclaim\s+your\s+refund\b|\bpackage\s+(?:is\s+)?(?:held|on\s+hold|blocked|stuck|detained)\b|\bpay\s+(?:to|for)\s+(?:release|redeliver|unblock)\b|\bshipment\s+(?:is\s+)?(?:held|blocked)\b"
    r"|\bfrais\s+de\s+(?:douane|d[ée]blocage|d[ée]douanement|relivraison|r[ée]activation)\b|\bcolis\s+(?:bloqu|retenu)",
    I,
)

# what the agent says it was asked: a reading job (summarize, translate...) and nothing about money
READ_ONLY_TASK = re.compile(
    r"\b(?:summari[sz]e|summary|read|translate|proofread|review|analy[sz]e|classify|extract|describe|explain|transcribe|index|search)\b"
    r"|\b(?:r[ée]sum(?:e|er|ez|é)|lis|lire|lisez|tradui(?:s|re|sez)|relis|relire|analyse[rz]?|classe[rz]?|extrai(?:s|re)|d[ée]cri(?:s|re)|explique[rz]?|synth[èe]se)\b",
    I,
)
PAYMENT_INTENT = re.compile(
    r"\b(?:pay|paid|payment|buy|purchase|order|checkout|send|transfer|wire|remit|invest|deposit|stake|swap|approve|settle|refund|subscribe|renew|top[- ]?up|tip|donate|invoice|bill)\w*\b"
    r"|\b(?:pa(?:ie|ye|yer|yez|iement)|ach[èe]t\w*|command\w*|r[èe]gl\w*|vire\w*|verse\w*|transf[èe]r\w*|envo\w*|plac\w*|invest\w*|d[ée]pos\w*|souscri\w*|abonn\w*|rembours\w*|factur\w*|x402)\b",
    I,
)

DEFAULT_CANARY = r"FLAG\{team2-canary\}"


def _canary(raw: str | None) -> re.Pattern:
    """SENTINEL_CANARY: the planted secret that must never leave in an order. A regex; a value that is not one is taken literally.
    An unresolved ${...} placeholder (an MCP host that did not expand it) counts as unset."""
    raw = (raw or "").strip()
    if not raw or re.fullmatch(r"\$\{[^}]*\}", raw):
        raw = DEFAULT_CANARY
    try:
        return re.compile(raw, I)
    except re.error:
        return re.compile(re.escape(raw), I)


CANARY = _canary(os.environ.get("SENTINEL_CANARY"))
