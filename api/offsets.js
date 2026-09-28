import { getServiceSupabase } from './_lib/supabase.js';
import { applyAdminCors, applyPublicCors, handlePreflight } from './_lib/cors.js';
import { validateSession } from './_lib/auth.js';

// ── LIB 07.08.2026 ────────────────────────────────────────────────────────
// Lib libil2cpp_07-08.so (md5 6d054013, 98.193.832 B).
// Update 31.07 -> 07.08: NAO houve reofuscacao (99% dos nomes identicos,
// 150.983/151.801) — o codigo so se moveu. Offsets estaticos re-localizados por
// sigmatch de corpo + autoridade de CLASSE no dump_07-08_CORRIGIDA.cpp.
// Ordem de autoridade: (1) teste in-game  (2) classe::metodo no dump  (3) sigmatch.
// (referencia offset 31.07 no comentario de cada linha)
//
// ⚠️ patches com `revisar: true` NAO devem ser aplicados: o corpo da funcao foi
// reescrito na 07.08 e o offset abaixo ainda e o da 31.07 — escrever nele
// aterra em endereco errado e trava o jogo.
//
// ── ANTI-BAN (11-08-2026) ─────────────────────────────────────────────────
// Os 4 patches marcados ANTIBAN vieram da libil2cpp_pached.so (md5 1608e02c) de
// terceiro e foram auditados: 15/15 caem em delta 0x0 de metodo, 0 colisao. Tipos
// batem byte a byte com Hook.h:2139-2258 (kARM64_RET/kARM64_FALSE64/kTRUE64).
//
// 🔑 `bjw::GetDeviceId` + `bkp::GetDeviceId` (FALSE64 = return null) DESBANIRAM o
// tablet do Ronni — VALIDADO IN-GAME 11-08. Isso REVOGA a regra antiga de
// docs/Functions/DeviceUnban.md:112 ("17.07: FALSE64 return null NAO desbana,
// servidor rejeita null") e DeviceUnban.h:46 ("trava o loading"): aquilo foi
// medido na 17.07 e nao vale para a 07-08. Medicao in-game vence documentacao —
// mesma licao do LKL_ANOGS_BYPASS (analise estatica de secao ELF perdeu p/ teste).
// ── TABELA DE 15 (11-08-2026) ─────────────────────────────────────────────
// Os 15 offsets conferidos um a um contra dump_07-08_CORRIGIDA.cpp:
// 15/15 caem em delta 0x0 de metodo (inicio real de funcao), 0 colisao, e todos
// tem folga >=8 B ate o proximo metodo (menor gap = 84 B em DayNightSystem).
//
// 🔑 COMO VALIDAR ESTA TABELA (nao ler, MEDIR): aplicar todos os ops numa copia da
// libil2cpp_07-08.so limpa tem de reproduzir a libil2cpp_pached.so byte a byte
// (md5 1608e02c). Esse teste pegou 2 erros meus na v4 que a leitura nao pegou —
// entre eles um patch na Torre que eu tinha "corrigido" para FALSE64 quando a lib
// validada simplesmente NAO TOCA nesse offset.
//
// 🔑 `FALSE64` em funcao `void` e SEMANTICAMENTE NEUTRO, nao um bug: FALSE64 =
// `mov x0,#0` + `ret`, e em `void` o chamador ignora x0 (caller-saved/scratch na
// AAPCS64). Ou seja FALSE64 e RET produzem o mesmo efeito nessas funcoes — a
// unica diferenca e' escrever 4 bytes a mais. Mantive o tipo exatamente como
// pedido pelo Ronni; nao "corrigi" para RET porque nao ha nada a corrigir.
//
// Cada label tem `i18n` (pt/en/ru/zh) — mesmos 4 idiomas do painel do KingRonni
// (`Lang::L`), para o APK poder mostrar na lingua do usuario. `label` continua
// em pt-BR para nao quebrar quem le so esse campo.
// ── 🔴 CORRECAO 11-08 (v4): teste in-game do Ronni ────────────────────────
// (1) O "Sem Recuo" da v3 NAO funcionava como o da lib 1608e02c: o tiro nao
//     espalhava mas SUBIA. Causa: o No Recoil e a SOMA DE DOIS patches —
//     Gun::pmj(float,bool) @0x2B6E1B8 + Gun::pmi(float) @0x2B6E110. A v3
//     separou o par em duas features ("Sem Recuo" + "Mira Pequena"), entao
//     marcar so a primeira entregava METADE do mecanismo. Fundidos no index 0.
// (2) 3 offsets REMOVIDOS por nao existirem na lib validada in-game (diff
//     binario 1608e02c vs 6d054013 = exatamente 15 patches / 115 bytes):
//       0x2AF5BF8 "Auxilio de Mira" = BattleCarPanel::UpdateCarInfo() (painel
//         de veiculo — o rotulo nunca correspondeu ao codigo)
//       0x27D6408 / 0x27D6458 "Remover Grama 1+2" = SkinnedMeshRenderHelper
//         ::Awake() e ::.ctor()
//     🔑 A grama continua funcionando: o patch que a lib boa usa e o TERCEIRO
//     (0x37D76E0, bph::baac), que ficou.
// (3) 0x3825230 "Parar Torre" trocado de RET para FALSE64: e
//     FlakGameObject::bazf() e RETORNA UM OBJETO (BasePlayerController). RET
//     puro deixa em x0 o valor residual = ponteiro-lixo de player controller;
//     FALSE64 devolve null, que o chamador pode testar. 🔑 RET so e' neutro em
//     funcao void. ⚠️ folga de apenas 8 B ate o proximo metodo — FALSE64 cabe
//     exato, nao trocar por patch maior.
// Prova de equivalencia: aplicar os 15 desta tabela na lib limpa reproduz a
// libil2cpp_pached.so byte a byte (md5 1608e02c) — nao "parecido", identico.
// ═══════════════════════════════════════════════════════════════════════════════
//  v5 — LIB 14-08 (md5 28c52598). Relocalizado em 14-08-2026.
// ═══════════════════════════════════════════════════════════════════════════════
// 🔴 Todo offset da v4 era da lib 07-08 e esta INVALIDO aqui. Mesmo sem reofuscacao
// (126/126 nomes intactos), o rearranjo de .text move tudo, e NAO existe delta global:
// os 10 offsets confirmados votam 10 deltas distintos.
//
// CRITERIO DE PROVA (o mesmo para os 10): corpo mascarado 100% + numero de instrucoes
// ate o RET identico. Comparo as instrucoes 07-08 vs 14-08 zerando os imediatos que a
// realocacao muda por construcao (BL/B, ADRP, LDR literal, imm12 de LDR/STR de
// metadata). Mede EFEITO (a funcao faz o mesmo), nao FORMA (parece prologo).
//
// 🔴 5 FEATURES REMOVIDAS — funcao REESCRITA na 14-08; o offset da dump cai no MEIO de
//    funcao (mesmo modo de falha que fez o No Recoil subir o tiro):
//      · Construcao Forcada   PartBehaviour::bimv        dump 0x27A0364 -> A8CF1DF1
//      · Trava de Mira Forte  BasePlayerController::vhq  dump 0x3651E04 -> 953F3CCC
//      · Respirar Sob Agua    SwimState::vwt             dump 0x3670320
//      · Parar Ataque Tanque  SystemTankController::zpw  dump 0x37C1308 -> C67F2806
//      · Sempre Dia           DayNightSystem::Update     dump 0x3ACFF64 -> C72230C1
//    Procurei o corpo equivalente na classe certa E na lib inteira: nao existe.
//    Reintroduzir exige alvo NOVO + teste in-game isolado, uma de cada vez.
//    🔑 `DayNightSystem::Update` prova que nao e' erro de base da dump: o nome NAO e'
//    ofuscado, logo o alvo esta certo — a funcao e' que mudou.
//
// ⚠️ Meu guard de prologo REPROVOU 4 dos 15 offsets que o Ronni validou in-game na
//    07-08 (FC1B0FEA, 6DBA33ED, FC1D0FEA, FC1D0FE8 = `str d`/`stp d`, prologo com
//    registrador de ponto flutuante). Testei a regra contra a lib validada ANTES de
//    acusar alvo: 11/15. Validador que reprova alvo certo tem defeito na REGRA.
const defaultOffsets = {
  // ══════════════════════════════════════════════════════════════════════════
  // v6 / LIB 21-08-2026 — libil2cpp_21-08.so
  // 11 features / 21 ops / 21 offsets unicos (contado rodando o literal no node,
  // nao a olho).
  //
  // 🔴 POR QUE A v5 PAROU DE FUNCIONAR: os offsets da v5 eram da lib 14-08, e a
  // baseline do patch_updater estava pior ainda (07-08). Medido na 21-08:
  // **0 de 15 offsets antigos caem em inicio de funcao** — todos aterram em
  // MEIO de metodo. Nao havia erro nenhum: escreve, diz OK, feature morta.
  //
  // CRITERIO DE ENTRADA (3 itens, nao 2 — o (b) e novo na 21-08):
  //   (a) prologo ARM64 valido na 1a instrucao
  //   (b) >= 25 de 60 instrucoes decodificam. Senao o metodo esta **CIFRADO**
  //       no .so e patch estatico e INUTIL: o runtime descriptografa por cima.
  //       7 alvos da 21-08 estao cifrados (lista no fim do arquivo).
  //   (c) folga >= 8 B ate o proximo metodo da dump
  //
  // 🔴 TIPO DE PATCH SEGUE O TIPO DE RETORNO — nao o gosto:
  //   void -> RET · bool -> TRUE64/FALSE64 conforme o efeito desejado ·
  //   objeto -> NUNCA RET puro (x0 fica com o `this` e o chamador usa isso como
  //   ponteiro = type confusion). Foi por isso que 'Parar Torre' saiu na v4.
  // ══════════════════════════════════════════════════════════════════════════
  version: '21-08-2026-v6-aprovado-ingame',
  patches: [
    // ── ARMA ────────────────────────────────────────────────────────────────
    // 🔑 4 ops num index unico. O par pmu+pmv e o No Recoil (descoberto in-game
    // pelo Ronni em 11-08: com so um dos dois, o spread morre mas o TIRO SOBE).
    // pmr/pms sao o bloom de movimento e de tiro — a 21-08 acrescentou os dois.
    // 🔴 Um override de ops substitui a lista INTEIRA: listar menos que os 4
    // aqui desfaz o mecanismo em silencio (foi exatamente o bug da v3).
    { index: 0,  label: 'Sem Recuo (real)', tab: 'arma',
      i18n: { pt:'Sem Recuo (real)', en:'True No Recoil', ru:'Без отдачи (реальная)', zh:'真实无后坐力' },
      ops: [{offset:'0x2B765D0',bytes:'FALSE64'},{offset:'0x2B76678',bytes:'FALSE64'},
            {offset:'0x2B74C30',bytes:'RET'},{offset:'0x2B761F0',bytes:'RET'}] },     // v6/21-08: Gun::pmu(float) @0x2B765D0 + Gun::pmv(float,bool) @0x2B76678, ambos void, corpo 100% contra a 14-08 · pmr() @0x2B74C30 e pms() @0x2B761F0 = bloom move/shoot, void -> RET. ✅ APROVADO IN-GAME 21-08. O 5o alvo (`plj` @0x2B71420) esta CIFRADO (4/60) e NAO entra
    { index: 1,  label: 'Mira Atraves das Paredes', tab: 'arma',
      i18n: { pt:'Mira Atraves das Paredes', en:'Aim Through Wall', ru:'Прицел через стены', zh:'穿墙瞄准' },
      ops: [{offset:'0x364C708',bytes:'TRUE64'},{offset:'0x364C98C',bytes:'FALSE64'}] },  // v6/21-08: vgk(MapObject)->bool @0x364C708 = TRUE64 (sempre "tem linha de visao"), corpo 110/110 · vgl(Vector3)->void @0x364C98C = FALSE64 (neutro em void), corpo 96/96. Prologo FP (`stp d`/`str d`) — legitimo; era o meu guard de prologo que reprovava por engano. ✅ APROVADO IN-GAME 21-08

    // ── MUNDO ───────────────────────────────────────────────────────────────
    { index: 2, label: 'Parar Ataque do Helicoptero', tab: 'mundo',
      i18n: { pt:'Parar Ataque do Helicoptero', en:'Stop Heli Attack', ru:'Остановить атаку вертолёта', zh:'停止直升机攻击' },
      ops: [{offset:'0x37B8810',bytes:'RET'}] },                                     // v6/21-08: zok->zol(int,Vector3,Vector3) @0x37B8810, void -> RET. Corpo 632/632 = 100% contra a 14-08 (que o Ronni ja validou in-game). Folga 2532 B
    // 🔑 O Ronni chama de "ESP Nome Amarelo"; a v5 dizia "Nome Verde". Fica o
    // nome dele: ele viu a cor no jogo, eu li a documentacao. In-game vence.
    { index: 3,  label: 'ESP Nome Amarelo (= Parar Ataque de Monstro)', tab: 'mundo',
      i18n: { pt:'ESP Nome Amarelo (= Parar Ataque de Monstro)', en:'Yellow Name ESP (= Stop Monster Attack)', ru:'ESP жёлтое имя (= остановить атаку монстров)', zh:'黄色名字 ESP（=停止怪物攻击）' },
      ops: [{offset:'0x385BFDC',bytes:'TRUE64'}] },                                  // v6/21-08: bbsg->bbsh(long)->bool @0x385BFDC = TRUE64. ✅ APROVADO IN-GAME 21-08. Uma feature so: a cor do nome e o ataque do monstro saem do MESMO metodo
    { index: 4,  label: 'Remover Grama do Mapa', tab: 'mundo',
      i18n: { pt:'Remover Grama do Mapa', en:'No Grass in Map', ru:'Убрать траву с карты', zh:'移除地图草地' },
      ops: [{offset:'0x37E2840',bytes:'FALSE64'}] },                                 // v6/21-08: babh(bqa) void override @0x37E2840, corpo 55/60. ✅ APROVADO IN-GAME 21-08. 🔴 UM op so: os 2 extras da v3 (0x27D6408 `Awake()`, 0x27D6458 `.ctor()`) matavam a inicializacao do SkinnedMeshRenderHelper — o rotulo "Remover Grama 1/3 e 2/3" nunca correspondeu ao codigo
    { index: 5,  label: 'Imune a Centry / Torre', tab: 'mundo',
      i18n: { pt:'Imune a Centry / Torre', en:'Sentry Immune', ru:'Иммунитет к турели', zh:'免疫哨戒炮' },
      ops: [{offset:'0x3838F20',bytes:'RET'},{offset:'0x382AC78',bytes:'RET'}] },     // v6/21-08 NOVA: bbdw(long) void @0x3838F20 (centry) + baxt(long) void @0x382AC78 (torre eletrica), 49/60 cada. ⏳ PENDENTE in-game — passam nos 3 criterios mas o Ronni ainda nao testou estes dois. 🔑 NAO e' o `bazf()` @0x3825230 que a v4 removeu (getter de objeto): estes sao void de verdade

    // ── JOGADOR ─────────────────────────────────────────────────────────────
    { index: 6,  label: 'Andar Debaixo da Agua', tab: 'jogador',
      i18n: { pt:'Andar Debaixo da Agua', en:'Walk Underwater', ru:'Ходить под водой', zh:'水下行走' },
      ops: [{offset:'0x3683F20',bytes:'RET'},{offset:'0x36832E4',bytes:'RET'}] },     // v6/21-08: vxs() @0x3683F20 (56/60) + vxr() @0x36832E4 (47/60), ambos void -> RET. ✅ APROVADO IN-GAME 21-08. 🔴 O 3o alvo do conjunto (`vxo` @0x366EFF0) esta CIFRADO (0/60): 2 de 3 e o maximo que patch estatico entrega aqui
    { index: 7, label: 'Bypass Forte + Desbanir Aparelho', tab: 'jogador',
      i18n: { pt:'Bypass Forte + Desbanir Aparelho', en:'Strong Bypass + Unban Device', ru:'Сильный обход + разбан устройства', zh:'强力绕过 + 设备解封' },
      ops: [{offset:'0x3708758',bytes:'FALSE64'},{offset:'0x370C3E8',bytes:'FALSE64'}] },  // v6/21-08: os DOIS `GetDeviceId()` -> string, FALSE64 = return null. Mesmo par que DESBANIU o tablet do Ronni em 11-08. ⏳ pendente in-game na 21-08 (mecanismo identico ao validado)

    // ── VEICULO ─────────────────────────────────────────────────────────────
    // 🔴 v6 TROCOU O ALVO, nao so o offset: a v5 usava `OnTriggerEnter` (dano que
    // eu CAUSO em outros); o certo e `nzf` = **OnHit** (dano que eu TOMO). Metodo
    // INVERSO, mesma classe, e o log de sucesso e identico nos dois — por isso a
    // feature parecia instalada e nao protegia nada. Corrigido e validado no V2.
    { index: 8, label: 'Carro Blindado', tab: 'veiculo',
      i18n: { pt:'Carro Blindado', en:'Armored Car', ru:'Бронированная машина', zh:'装甲车' },
      ops: [{offset:'0x26BD8C4',bytes:'FALSE64'}] },                                 // v6/21-08: CarController::nzf(MapObject) = OnHit @0x26BD8C4, corpo 52/60, folga 880 B

    // ── CONSTRUCAO ──────────────────────────────────────────────────────────
    { index: 9, label: 'Forcar Construcao', tab: 'construcao',
      i18n: { pt:'Forcar Construcao', en:'Force Build', ru:'Принудительная стройка', zh:'强制建造' },
      ops: [{offset:'0x27AC4F4',bytes:'TRUE64'},{offset:'0x27AADBC',bytes:'RET'},
            {offset:'0x27AA7FC',bytes:'FALSE64'}] },                                  // v6/21-08 NOVA: birn()->bool @0x27AC4F4 = TRUE64 · birv(PartBehaviour) void @0x27AADBC = RET · birx(PartBehaviour)->bool @0x27AA7FC = FALSE64. ⏳ PENDENTE in-game. 🔴 O 4o alvo (`bioq`, CheckEnterBoxCollider) esta CIFRADO (2/60) — no V2 (runtime, resolve por nome) ele FUNCIONA e foi o que consertou o Force Build; aqui, em patch estatico, nao alcanca. As duas rotas nao sao intercambiaveis

    // ── EXPLOSIVOS ──────────────────────────────────────────────────────────
    // 🔑 Ja existe no V2 (KingRonni) como "Rpg multiwall": hooks nos MESMOS `mcw`/
    // `mcy` (Hook.h:5225-5226), resolvidos por NOME em runtime. Esta e a rota de
    // patch estatico da mesma feature — as duas coexistem, cada app usa a sua.
    // Os dois sao `static bool` -> TRUE64 nos dois ("sempre pode atravessar").
    { index: 10, label: 'Perfuracao de Barreira RPG', tab: 'arma',
      i18n: { pt:'Perfuracao de Barreira RPG', en:'RPG Multiwall', ru:'РПГ сквозь стены', zh:'RPG穿墙' },
      ops: [{offset:'0x39B5570',bytes:'TRUE64'},{offset:'0x39B5494',bytes:'TRUE64'}] }     // v6/21-08 NOVA: hb::mcw(GameObject,Vector3,Vector3) static bool @0x39B5570 (CheckNoBlock) + hb::mcy(MapObject) static bool @0x39B5494. ✅ APROVADO IN-GAME 21-08
  ]
};

// ══════════════════════════════════════════════════════════════════════════════
// NAO ENTRAM NA v6 — motivo MEDIDO em 21-08 (nao chute, nao leitura):
//
// CIFRADOS no .so (o patch grava, o updater diz OK, o runtime descriptografa por
// cima => feature morta com log verde). Detector: tools/offset_updater_core.py
// :: is_crypto(), que concordou 8/8 com a contagem de 60 instrucoes:
//   Folego Infinito       vwt  @0x367F2E4  0/60  <- era codigo LIMPO na 07-08!
//   Andar sob agua (3/3)  vxo  @0x366EFF0  0/60
//   Imune a Tank          zrb  @0x37BFB88  2/60
//   Force Build (4/4)     bioq @0x279FEB0  2/60
//   Entrar Server Mod     ttl  @0x35DF104  7/60
//   Entrar Server Mod     ttm  @0x35DF658  5/60
//   Sem Recuo (5/5)       plj  @0x2B71420  4/60
// 🔑 "funcionava na versao passada" NAO e argumento: o Folego era limpo na 07-08
// e o jogo passou a cifrar. Medir a cifra a cada update.
//
// RECICLADO / FUNCAO REESCRITA (o nome vive, o corpo nao existe mais):
//   'Trava de Mira Forte' `vhq` — 58 instrucoes na 07-08; hoje o nome aponta para
//     um getter de 2 instrucoes, e o corpo original nao esta em lugar nenhum da
//     lib (varri a .text inteira, inclusive com 90% de tolerancia).
//   'No Monster' 0x35F7EC0 e 'Mira+ cruzada' 0x2B67A24 — [REVISAR] desde 07-08.
//
// SO RUNTIME (precisam de `this`, loop por frame, ou chamar metodo do jogo —
// patch estatico grava bytes, nao executa logica):
//   Speed hack moto/carro · Permissao falsa · Sem dano de queda · Ghost in the
//   Tank · RPG Splash · Deepwater Overdrive · Imunidade navio patrulha ·
//   Sempre Dia (DayNightSystem reescrita na 14-08)
// ══════════════════════════════════════════════════════════════════════════════

export default async function handler(req, res) {
  if (req.method === 'GET') {
    applyPublicCors(res);
  } else {
    applyAdminCors(req, res);
  }
  if (handlePreflight(req, res)) return;

  const supabase = getServiceSupabase();

  if (req.method === 'GET') {
    const { data, error } = await supabase
      .from('settings').select('value').eq('key', 'offsets_config').maybeSingle();
    if (error || !data) return res.status(200).json(defaultOffsets);

    const stored = data.value;
    // Se a versão no banco for mais antiga que o defaultOffsets, migra automaticamente
    if (stored.version !== defaultOffsets.version) {
      await supabase.from('settings')
        .upsert({ key: 'offsets_config', value: defaultOffsets }, { onConflict: 'key' });
      return res.status(200).json(defaultOffsets);
    }

    // Mesmo na versão certa: garante bytes corretos e offsets atualizados.
    // 🔑 A chave é o `index`, e cada versão RENUMEROU as features. Este override só é
    // seguro porque a migração por `version` acima já reescreveu qualquer config de
    // versão anterior — quando chegamos aqui, stored.version === v4 e o index 0 é de
    // fato o Sem Recuo.
    //
    // 🔴 11-08 v4: o override TEM DE TER OS DOIS OPS. Na v3 ele forçava apenas
    // `0x2B6E1B8`, e isso *desfazia* o par pmi+pmj em qualquer config salva pelo admin —
    // recriando exatamente o bug do tiro subindo. Um override de ops substitui a lista
    // inteira, então listar um op só é destrutivo, não aditivo.
    // 🔴 v5: RENUMERADO **e** RE-OFFSETADO na mesma passada. Remover 5 features renumerou
    // tudo (Grama saiu de 6 para 4) e a lib mudou de 07-08 para 14-08. Um override que
    // ficasse com o índice velho apontaria para a feature errada, e um que ficasse com o
    // offset velho gravaria FALSE64 no meio de outra função — dos dois jeitos, calado.
    // 🔑 Ao mexer em `defaultOffsets`, conferir este bloco no mesmo commit. Sempre.
    const BYTE_OVERRIDES = {
      // 🔴 v6/21-08: RE-OFFSETADO. Este bloco roda por `index` e um override de
      // ops substitui a lista INTEIRA. Se ficasse com os offsets da v5 (14-08),
      // reescreveria os offsets novos pelos velhos em toda config ja salva pelo
      // admin — gravando no meio de outra funcao, calado. Conferir SEMPRE junto
      // com `defaultOffsets`, no mesmo commit.
      0: { ops: [
        { offset: '0x2B765D0', bytes: 'FALSE64' },   // Gun::pmu(float)
        { offset: '0x2B76678', bytes: 'FALSE64' },   // Gun::pmv(float,bool) — a outra metade do par
        { offset: '0x2B74C30', bytes: 'RET' },       // Gun::pmr() bloom de movimento
        { offset: '0x2B761F0', bytes: 'RET' }        // Gun::pms() bloom de tiro
      ] },
      // Grama: index 4. UM op — os 2 extras da v3 (0x27D6408 Awake, 0x27D6458
      // .ctor) matavam a inicializacao do SkinnedMeshRenderHelper.
      4: { ops: [{ offset: '0x37E2840', bytes: 'FALSE64' }] }
    };
    let needsFix = false;
    const fixed = {
      ...stored,
      patches: stored.patches.map(p => {
        const override = BYTE_OVERRIDES[p.index];
        if (!override) return p;
        // override com ops completo: substitui tudo
        if (override.ops) {
          const currentOpsStr = JSON.stringify(p.ops);
          const newOpsStr = JSON.stringify(override.ops);
          if (currentOpsStr !== newOpsStr) { needsFix = true; return { ...p, ops: override.ops }; }
          return p;
        }
        // override só de bytes: aplica em cada op
        if (override.bytes) {
          if (p.ops.some(op => op.bytes !== override.bytes)) {
            needsFix = true;
            return { ...p, ops: p.ops.map(op => ({ ...op, bytes: override.bytes })) };
          }
        }
        return p;
      })
    };
    if (needsFix) {
      await supabase.from('settings')
        .upsert({ key: 'offsets_config', value: fixed }, { onConflict: 'key' });
      return res.status(200).json(fixed);
    }

    return res.status(200).json(stored);
  }

  if (req.method === 'POST') {
    const sess = await validateSession(req, res);
    if (!sess) return;
    const body = req.body;
    if (!body || !body.version || !Array.isArray(body.patches)) {
      return res.status(400).json({ error: 'Invalid body: version + patches[] required' });
    }
    const { error: upsertErr } = await supabase.from('settings')
      .upsert({ key: 'offsets_config', value: body }, { onConflict: 'key' });
    if (upsertErr) return res.status(500).json({ error: upsertErr.message });
    return res.status(200).json({ ok: true, version: body.version });
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
