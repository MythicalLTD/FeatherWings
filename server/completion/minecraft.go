package completion

// Minecraft is a built-in completion profile for common vanilla / Paper-style
// console commands. Eggs for any app should prefer shipping their own tree via
// process_configuration.completion; this profile is only a convenience.
func Minecraft() *Tree {
	modes := []string{"survival", "creative", "adventure", "spectator"}
	difficulties := []string{"peaceful", "easy", "normal", "hard"}
	weather := []string{"clear", "rain", "thunder"}
	timeSet := []string{"day", "night", "noon", "midnight"}
	gameRules := []string{
		"announceAdvancements", "commandBlockOutput", "disableElytraMovementCheck",
		"doDaylightCycle", "doEntityDrops", "doFireTick", "doImmediateRespawn",
		"doInsomnia", "doLimitedCrafting", "doMobLoot", "doMobSpawning",
		"doPatrolSpawning", "doTileDrops", "doTraderSpawning", "doWeatherCycle",
		"drowningDamage", "fallDamage", "fireDamage", "forgiveDeadPlayers",
		"freezeDamage", "keepInventory", "logAdminCommands", "maxCommandChainLength",
		"maxEntityCramming", "mobGriefing", "naturalRegeneration", "playersSleepingPercentage",
		"randomTickSpeed", "reducedDebugInfo", "sendCommandFeedback", "showDeathMessages",
		"spawnRadius", "spectatorsGenerateChunks", "universalAnger",
	}
	bools := []string{"true", "false"}
	effects := []string{
		"speed", "slowness", "haste", "mining_fatigue", "strength", "instant_health",
		"instant_damage", "jump_boost", "nausea", "regeneration", "resistance",
		"fire_resistance", "water_breathing", "invisibility", "blindness", "night_vision",
		"hunger", "weakness", "poison", "wither", "health_boost", "absorption",
		"saturation", "glowing", "levitation", "luck", "unluck", "slow_falling",
		"conduit_power", "dolphins_grace", "bad_omen", "hero_of_the_village",
	}
	items := []string{
		"stone", "dirt", "grass_block", "cobblestone", "oak_planks", "oak_log",
		"stick", "diamond", "iron_ingot", "gold_ingot", "coal", "diamond_sword",
		"diamond_pickaxe", "bow", "arrow", "bread", "cooked_beef", "ender_pearl",
		"ender_eye", "obsidian", "torch", "chest", "furnace", "crafting_table",
		"water_bucket", "lava_bucket", "bucket", "oak_boat", "minecart",
		"writable_book", "book", "paper", "map", "compass", "clock",
		"netherite_ingot", "netherite_sword", "totem_of_undying", "elytra",
	}

	return &Tree{
		Commands: map[string]Command{
			"help":       {},
			"list":       {},
			"seed":       {},
			"version":    {},
			"plugins":    {},
			"reload":     {},
			"stop":       {},
			"save-all":   {},
			"save-on":    {},
			"save-off":   {},
			"whitelist":  {Args: []ArgSpec{{Values: []string{"add", "remove", "list", "on", "off", "reload"}}, {Any: true}}},
			"ban":        {Args: []ArgSpec{{Any: true}}},
			"ban-ip":     {Args: []ArgSpec{{Any: true}}},
			"pardon":     {Args: []ArgSpec{{Any: true}}},
			"pardon-ip":  {Args: []ArgSpec{{Any: true}}},
			"kick":       {Args: []ArgSpec{{Any: true}}},
			"op":         {Args: []ArgSpec{{Any: true}}},
			"deop":       {Args: []ArgSpec{{Any: true}}},
			"kill":       {Args: []ArgSpec{{Any: true}}},
			"clear":      {Args: []ArgSpec{{Any: true}}},
			"gamemode":   {Args: []ArgSpec{{Values: modes}, {Any: true}}},
			"defaultgamemode": {Args: []ArgSpec{{Values: modes}}},
			"difficulty": {Args: []ArgSpec{{Values: difficulties}}},
			"weather":    {Args: []ArgSpec{{Values: weather}, {Any: true}}},
			"time": {Args: []ArgSpec{
				{Values: []string{"set", "add", "query"}},
				{Values: append(append([]string{}, timeSet...), "daytime", "gametime", "day")},
			}},
			"gamerule": {Args: []ArgSpec{{Values: gameRules}, {Values: bools}}},
			"xp":       {Args: []ArgSpec{{Any: true}, {Any: true}}},
			"experience": {Args: []ArgSpec{
				{Values: []string{"add", "set", "query"}},
				{Any: true},
				{Any: true},
				{Values: []string{"levels", "points"}},
			}},
			"effect": {Args: []ArgSpec{
				{Values: []string{"give", "clear"}},
				{Any: true},
				{Values: effects},
			}},
			"enchant": {Args: []ArgSpec{{Any: true}, {Any: true}, {Any: true}}},
			"give":    {Args: []ArgSpec{{Any: true}, {Values: items}, {Any: true}}},
			"tp":      {Args: []ArgSpec{{Any: true}, {Any: true}}},
			"teleport": {Args: []ArgSpec{{Any: true}, {Any: true}}},
			"tell":    {Args: []ArgSpec{{Any: true}, {Any: true}}},
			"msg":     {Args: []ArgSpec{{Any: true}, {Any: true}}},
			"w":       {Args: []ArgSpec{{Any: true}, {Any: true}}},
			"say":     {Args: []ArgSpec{{Any: true}}},
			"me":      {Args: []ArgSpec{{Any: true}}},
			"title": {Args: []ArgSpec{
				{Any: true},
				{Values: []string{"clear", "reset", "title", "subtitle", "actionbar", "times"}},
			}},
			"playsound": {Args: []ArgSpec{{Any: true}, {Values: []string{"master", "music", "record", "weather", "block", "hostile", "neutral", "player", "ambient", "voice"}}, {Any: true}}},
			"particle":  {Args: []ArgSpec{{Any: true}}},
			"summon":    {Args: []ArgSpec{{Any: true}}},
			"setblock":  {Args: []ArgSpec{{Any: true}, {Any: true}, {Any: true}, {Any: true}}},
			"fill":      {Args: []ArgSpec{{Any: true}}},
			"clone":     {Args: []ArgSpec{{Any: true}}},
			"data": {Args: []ArgSpec{
				{Values: []string{"get", "merge", "modify", "remove"}},
				{Values: []string{"block", "entity", "storage"}},
			}},
			"execute": {Args: []ArgSpec{{Values: []string{"as", "at", "positioned", "aligned", "facing", "rotated", "in", "anchored", "if", "unless", "store", "run"}}}},
			"function": {Args: []ArgSpec{{Any: true}}},
			"schedule": {Args: []ArgSpec{{Values: []string{"function", "clear"}}, {Any: true}}},
			"tag":      {Args: []ArgSpec{{Any: true}, {Values: []string{"add", "remove", "list"}}, {Any: true}}},
			"team": {Args: []ArgSpec{
				{Values: []string{"list", "add", "remove", "empty", "join", "leave", "modify"}},
			}},
			"scoreboard": {Args: []ArgSpec{
				{Values: []string{"objectives", "players", "players"}},
			}},
			"bossbar": {Args: []ArgSpec{
				{Values: []string{"add", "remove", "list", "set", "get"}},
			}},
			"worldborder": {Args: []ArgSpec{
				{Values: []string{"add", "center", "damage", "get", "set", "warning"}},
			}},
			"spreadplayers": {Args: []ArgSpec{{Any: true}}},
			"forceload":     {Args: []ArgSpec{{Values: []string{"add", "remove", "query"}}, {Any: true}}},
			"locate":        {Args: []ArgSpec{{Values: []string{"structure", "biome", "poi"}}, {Any: true}}},
			"locatebiome":   {Args: []ArgSpec{{Any: true}}},
			"advancement": {Args: []ArgSpec{
				{Values: []string{"grant", "revoke"}},
				{Any: true},
				{Values: []string{"only", "through", "from", "until", "everything"}},
			}},
			"recipe": {Args: []ArgSpec{
				{Values: []string{"give", "take"}},
				{Any: true},
				{Any: true},
			}},
			"loot": {Args: []ArgSpec{
				{Values: []string{"give", "insert", "spawn", "replace"}},
			}},
			"item": {Args: []ArgSpec{
				{Values: []string{"replace", "modify"}},
				{Values: []string{"block", "entity"}},
			}},
			"attribute": {Args: []ArgSpec{{Any: true}, {Any: true}, {Values: []string{"get", "base", "modifier"}}}},
			"damage":    {Args: []ArgSpec{{Any: true}, {Any: true}}},
			"ride":      {Args: []ArgSpec{{Any: true}, {Values: []string{"mount", "dismount"}}}},
			"spectate":  {Args: []ArgSpec{{Any: true}, {Any: true}}},
			"place":     {Args: []ArgSpec{{Values: []string{"feature", "jigsaw", "structure", "template"}}, {Any: true}}},
			"fillbiome": {Args: []ArgSpec{{Any: true}}},
			"random":    {Args: []ArgSpec{{Values: []string{"value", "roll", "reset"}}}},
			"return":    {Args: []ArgSpec{{Values: []string{"fail", "run"}}, {Any: true}}},
			"tick":      {Args: []ArgSpec{{Values: []string{"query", "rate", "step", "sprint", "freeze", "unfreeze"}}}},
			"publish":   {Args: []ArgSpec{{Any: true}}},
			"debug":     {Args: []ArgSpec{{Values: []string{"start", "stop", "function"}}}},
			"perf":      {Args: []ArgSpec{{Values: []string{"start", "stop"}}}},
			"jfr":       {Args: []ArgSpec{{Values: []string{"start", "stop"}}}},
			"spark":     {Args: []ArgSpec{{Values: []string{"profiler", "tps", "health", "heap", "tickmonitor"}}}},
			"paper":     {Args: []ArgSpec{{Values: []string{"dumpitem", "filltrash", "syncload", "version", "reload"}}}},
			"purpur":    {Args: []ArgSpec{{Values: []string{"reload", "version"}}}},
			"spigot":    {Args: []ArgSpec{{Values: []string{"reload"}}}},
			"bukkit":    {Args: []ArgSpec{{Values: []string{"reload", "version"}}}},
			"timings":   {Args: []ArgSpec{{Values: []string{"on", "off", "reset", "paste", "report", "verbon", "verboff"}}}},
		},
	}
}
