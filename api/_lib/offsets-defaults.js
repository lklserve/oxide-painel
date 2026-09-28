// Constantes de patch + tabela default da lib 18-06-2026.
// Espelha o switch hardcoded de native-lib.cpp (mantenha sincronizado).

// Tipos de patch -> hex ARM64
export const PATCH_TYPES = {
    RET: 'C0035FD6',
    TRUE64: '200080D2C0035FD6',
    FALSE64: '000080D2C0035FD6',
    FALSE32: '00008052C0035FD6',
    MOVZ_X1: '010080D2C0035FD6',
    MOVZ_X0_4: '800080D2C0035FD6'
};

// Offsets PROIBIDOS (regra do projeto: crash/trava).
export const BLOCKED_OFFSETS = ['0x151366C', '0x242CE0C', '0x2443968'];

// Default = lib 18-06-2026.
export const defaultOffsets = {
    version: '18-06-2026',
    patches: {
        aim_assist: [['0x192AD3C', 'RET']],
        no_recoil: [['0x1927CE8', 'FALSE64']],
        wallhack_linecast: [
            ['0x4070750', 'FALSE32']
        ],
        no_spread: [['0x192C16C', 'FALSE64']],
        wall_penetration: [['0x273F3DC', 'TRUE64']],
        bomb_splash: [['0x273F2F8', 'TRUE64']],
        esp_green: [['0x25E3C08', 'TRUE64']],
        esp_yellow: [['0x25C43A4', 'TRUE64']],
        always_day: [['0x286A180', 'RET']],
        remove_grass: [['0x255F918', 'FALSE64']],
        force_build: [['0x1540DEC', 'MOVZ_X1']],
        tank_heli_no_attack: [['0x253C6C8', 'RET']],
        heli_no_attack: [['0x2535318', 'RET']],
        ghost_tank: [
            ['0x25407A4', 'FALSE64'], ['0x253EF1C', 'FALSE64'],
            ['0x253E3E0', 'FALSE64'], ['0x2540994', 'FALSE64'],
            ['0x2532CA4', 'FALSE64'], ['0x2532D20', 'FALSE64'],
            ['0x2532E54', 'FALSE64'], ['0x2532EF4', 'FALSE64']
        ],
        freeze_monsters: [['0x23914D0', 'FALSE64']],
        infinite_breath: [['0x24015A8', 'FALSE64']],
        walk_underwater: [['0x2401840', 'RET']],
        underwater_damage: [['0x18162B4', 'FALSE64']],
        no_fall_damage: [['0x23E4C70', 'FALSE64']],
        anti_ban: [
            ['0x24842E0', 'FALSE32'], ['0x249BD8C', 'RET']
        ],
        no_shake: [['0x26B186C', 'RET']],
        vehicle_godmode: [
            ['0x146ABAC', 'FALSE64'], ['0x146A4C4', 'FALSE64'],
            ['0x146AF28', 'FALSE64'], ['0x1467018', 'FALSE64'],
            ['0x15946B4', 'FALSE64'], ['0x1595704', 'FALSE64'],
            ['0x1595BC4', 'FALSE64'], ['0x15952E0', 'FALSE64']
        ],
        car_speedhack: [['0x146AA0C', 'FALSE64']],
        bike_speedhack: [['0x1592448', 'FALSE64']]
    }
};
