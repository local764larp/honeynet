package credentials

// The corpus below is the population a node's own passwords are drawn from.
//
// Drawing from the same lists attackers spray is the entire trick. The node
// holds exactly one password per account, like any real machine, so it can
// never contradict itself under probing -- and because that password came off
// the head of the same wordlist the botnet is working through, the botnet still
// arrives at it.
//
// Two tiers, because prevalence is not uniform. Spray traffic is dominated by a
// very short head; an account whose password is drawn uniformly from a large
// list would almost never be guessed, and the sensor would collect credential
// attempts and nothing else.

// headPasswords is what actually gets tried in the first few hundred guesses of
// a real spray: breach-list leaders, IoT and DVR firmware defaults, and the
// vendor defaults that the Mirai lineage carries hardcoded.
//
// A node's weak accounts draw from here, so that a botnet working a standard
// list reaches the node's password early in its run.
var headPasswords = []string{
	// Breach-list leaders.
	"123456", "password", "12345678", "qwerty", "123456789", "12345",
	"1234", "111111", "1234567", "dragon", "123123", "abc123", "letmein",
	"monkey", "shadow", "sunshine", "12345678910", "654321", "master",
	"666666", "qwertyuiop", "123321", "mustang", "1234567890", "888888",
	"princess", "trustno1", "000000", "iloveyou", "password1", "admin123",

	// Credentials that arrive paired with a specific account far more often
	// than at random -- these are what makes root:root and admin:admin the
	// two most-attempted pairs on the internet.
	"root", "admin", "toor", "pass", "test", "guest", "user", "default",
	"changeme", "welcome", "administrator", "supervisor", "support",
	"service", "operator", "manager", "system", "public", "private",

	// IoT, DVR and camera firmware defaults. Hardcoded in the Mirai and
	// Gafgyt families and sprayed constantly.
	"vizxv", "xc3511", "juantech", "anko", "zlxx", "7ujMko0admin",
	"7ujMko0vizxv", "ikwb", "dreambox", "realtek", "meinsm", "smcadmin",
	"klv123", "klv1234", "jvbzd", "hi3518", "xmhdipc", "cat1029",
	"hslwjkl123", "20080826", "1001chin", "tsgoingon", "solokey",
	"tlJwpbo6", "fliradmin", "telecomadmin", "aquario", "nE7jA%5m",

	// Appliance and single-board defaults.
	"ubnt", "raspberry", "cisco", "calvin", "openwrt", "nagiosadmin",
}

// tailPasswords are drawn on by accounts that are meant to resist guessing.
//
// Real machines are not uniformly weak. A box where every account falls to the
// first wordlist is as unusual as one where none do, so most accounts on a node
// get a password from here -- recognisably human, never in the sprayed head,
// and in practice never guessed.
var tailPasswords = []string{
	"chelsea", "arsenal", "liverpool", "barcelona", "ferrari", "porsche",
	"corvette", "mustang01", "yamaha", "phoenix", "falcon", "panther",
	"cobra", "viper", "raptor", "dolphin", "samurai", "warrior", "sniper",
	"champion", "victory", "freedom", "whatever", "internet", "computer",
	"starwars", "pokemon", "minecraft", "gandalf", "matrix", "neo",
	"jennifer", "michelle", "stephanie", "kathleen", "caroline",
	"christine", "rebecca", "virginia", "patrick", "anthony", "brandon",
	"jonathan", "nicholas", "benjamin", "alexander", "christopher",
	"summer2019", "winter2020", "spring2021", "autumn2022", "london2018",
	"hunter77", "ranger22", "pepper99", "ginger14", "silver63", "orange41",
	"maggie08", "buster31", "harley56", "cookie72", "banana19", "flower85",
}

// weakAccounts are the usernames that, when present on a node, are the ones
// likely to carry a head password.
//
// Concentrating the weakness here rather than spreading it evenly is what a
// real compromised-by-neglect box looks like: the shared operational accounts
// rot, the named human accounts mostly do not.
var weakAccounts = map[string]bool{
	"root": true, "admin": true, "administrator": true, "user": true,
	"test": true, "guest": true, "demo": true, "oracle": true, "pi": true,
	"support": true, "service": true, "supervisor": true, "operator": true,
	"backup": true, "deploy": true, "ftp": true, "ftpuser": true,
	"mysql": true, "postgres": true, "tomcat": true, "jenkins": true,
	"ubnt": true, "default": true, "system": true, "telnet": true,
}
